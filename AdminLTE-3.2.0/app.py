from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate  # Nueva importación
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from functools import wraps
import bcrypt
from sqlalchemy.sql import text
from sqlalchemy import func
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from wtforms import SelectField, IntegerField
from wtforms.validators import NumberRange
from datetime import timezone

# Crear la aplicación Flask
app = Flask(__name__)

# Configurar la conexión a PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://adminlte_user:123456@localhost:5432/adminlte_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'lfgp_sena'  # Cambia esto por una clave secreta única

# Inicializar SQLAlchemy
db = SQLAlchemy(app)

#Inicializar Flask-Migrate
migrate = Migrate(app, db)


# Configurar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirige a esta ruta si no está autenticado

# Agregar el filtro 'zip' al entorno de Jinja2
app.jinja_env.filters['zip'] = zip


#creación de fomulario seguro con protección CSRF
class LoginForm(FlaskForm):
    email = StringField('Correo Electrónico', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')

class InventarioForm(FlaskForm):
    producto_id = SelectField('Producto', coerce=int, validators=[DataRequired()])
    cantidad = IntegerField('Cantidad', validators=[DataRequired(), NumberRange(min=0, message="La cantidad no puede ser negativa.")])
    submit = SubmitField('Guardar')


# Definir los modelos (tablas)
class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Cambiado de 'contraseña' a 'password'
    rol = db.Column(db.String(50), nullable=False, default='usuario')

    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
    
class HistorialConfiguracion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    clave = db.Column(db.String(50), nullable=False)
    valor_anterior = db.Column(db.String(100))
    valor_nuevo = db.Column(db.String(100), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    fecha = db.Column(db.DateTime, nullable=False)
    usuario = db.relationship('Usuario', backref='cambios_configuracion')

    def __repr__(self):
        return f"<HistorialConfiguracion {self.clave}>"

class Cliente(db.Model):
    __tablename__ = 'clientes'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    telefono = db.Column(db.String(20))
    fecha_registro = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    pedidos = db.relationship('Pedido', back_populates='cliente', cascade='all, delete-orphan')

class Producto(db.Model):
    __tablename__ = 'productos'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)  # Agregamos descripción
    precio = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)

class Inventario(db.Model):
    __tablename__ = 'inventario'
    id = db.Column(db.Integer, primary_key=True)
    producto_id = db.Column(db.Integer, db.ForeignKey('productos.id'), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    fecha_actualizacion = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    producto = db.relationship('Producto', backref='inventarios')

class Pedido(db.Model):
    __tablename__ = 'pedidos'
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('clientes.id'), nullable=False)
    fecha = db.Column(db.Date, nullable=False)
    estado = db.Column(db.String(20), nullable=False)
    cliente = db.relationship('Cliente', back_populates='pedidos')
    productos = db.relationship('PedidoProducto', back_populates='pedido', cascade='all, delete-orphan')

class PedidoProducto(db.Model):
    __tablename__ = 'pedido_productos'
    pedido_id = db.Column(db.Integer, db.ForeignKey('pedidos.id'), primary_key=True)
    producto_id = db.Column(db.Integer, db.ForeignKey('productos.id'), primary_key=True)
    cantidad = db.Column(db.Integer, nullable=False)
    pedido = db.relationship('Pedido', back_populates='productos')
    producto = db.relationship('Producto')

class Configuracion(db.Model):
    __tablename__ = 'configuraciones'
    id = db.Column(db.Integer, primary_key=True)
    clave = db.Column(db.String(50), unique=True, nullable=False)
    valor = db.Column(db.String(50), nullable=False)

class ConfiguracionHistorial(db.Model):
    __tablename__ = 'configuraciones_historial'
    id = db.Column(db.Integer, primary_key=True)
    configuracion_id = db.Column(db.Integer, db.ForeignKey('configuraciones.id'), nullable=False)
    clave = db.Column(db.String(50), nullable=False)
    valor_anterior = db.Column(db.String(100), nullable=False)
    valor_nuevo = db.Column(db.String(100), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    fecha = db.Column(db.DateTime, nullable=False, default=datetime.now)
    configuracion = db.relationship('Configuracion', backref=db.backref('historial', lazy=True))
    usuario = db.relationship('Usuario', backref=db.backref('configuraciones_historial', lazy=True))


    
#******************************************************************************

# Decorador para restringir acceso a administradores
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.rol != 'admin':
            flash("Acceso denegado: se requiere rol de administrador.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Cargar usuario para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Función para agregar datos de prueba
def agregar_datos_prueba():
    if Usuario.query.count() == 0:
        admin = Usuario(nombre="Admin User", email="admin@example.com", rol="admin")
        admin.set_password("admin123")
        usuario = Usuario(nombre="Regular User", email="user@example.com", rol="usuario")
        usuario.set_password("user123")
        db.session.add(admin)
        db.session.add(usuario)

    if Cliente.query.count() == 0:
        clientes = [
            Cliente(nombre="Juan Pérez", email="juan@example.com", telefono="123456789", fecha_registro=datetime.now()),
            Cliente(nombre="María Gómez", email="maria@example.com", telefono="987654321", fecha_registro=datetime.now())
        ]
        for cliente in clientes:
            db.session.add(cliente)

    if Producto.query.count() == 0:
        productos = [
            Producto(nombre="Producto A", descripcion="Descripción de Producto A", precio=10.99, stock=50),
            Producto(nombre="Producto B", descripcion="Descripción de Producto B", precio=20.49, stock=5)
        ]
        for producto in productos:
            db.session.add(producto)
            db.session.flush()  # Obtener ID del producto
            inventario = Inventario(
                producto_id=producto.id,
                cantidad=producto.stock,
                fecha_actualizacion=datetime.now()
            )
            movimiento = MovimientoInventario(
                producto_id=producto.id,
                tipo_movimiento="entrada",
                cantidad=producto.stock,
                usuario_id=1  # Asumimos el ID del admin como 1
            )
            db.session.add(inventario)
            db.session.add(movimiento)

    db.session.commit()

    if Inventario.query.count() == 0:
        producto_a = Producto.query.filter_by(nombre="Producto A").first()
        producto_b = Producto.query.filter_by(nombre="Producto B").first()
        inventarios = [
            Inventario(producto_id=producto_a.id, cantidad=50, fecha_actualizacion=datetime.now()),
            Inventario(producto_id=producto_b.id, cantidad=5, fecha_actualizacion=datetime.now())
        ]
        for inventario in inventarios:
            db.session.add(inventario)

    if Pedido.query.count() == 0:
        cliente_1 = Cliente.query.filter_by(nombre="Juan Pérez").first()
        cliente_2 = Cliente.query.filter_by(nombre="María Gómez").first()
        producto_a = Producto.query.filter_by(nombre="Producto A").first()
        producto_b = Producto.query.filter_by(nombre="Producto B").first()
        
        pedido_1 = Pedido(cliente_id=cliente_1.id, fecha=datetime.now(), estado="pendiente")
        pedido_2 = Pedido(cliente_id=cliente_2.id, fecha=datetime.now(), estado="completado")
        
        pedido_1.productos = [PedidoProducto(producto=producto_a, cantidad=2)]
        pedido_2.productos = [
            PedidoProducto(producto=producto_a, cantidad=1),
            PedidoProducto(producto=producto_b, cantidad=3)
        ]
        
        db.session.add(pedido_1)
        db.session.add(pedido_2)

    if Configuracion.query.count() == 0:
        configuraciones = [
            Configuracion(clave="umbral_stock", valor="10")
        ]
        for config in configuraciones:
            db.session.add(config)

    db.session.commit()

#******************************************************************************    

# Rutas
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario and usuario.check_password(password):
            login_user(usuario)
            session['rol'] = usuario.rol  # Guardar el rol en la sesión
            flash("Inicio de sesión exitoso.", "success")
            return redirect(url_for('home'))
        else:
            flash("Email o contraseña incorrectos.", "danger")
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Has cerrado sesión.", "success")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    fecha_inicio_mes = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    pedidos_completados = Pedido.query.filter(
        Pedido.estado == 'completado',
        Pedido.fecha >= fecha_inicio_mes
    ).all()
    total_ventas = sum(
        sum(pedido_producto.producto.precio * pedido_producto.cantidad for pedido_producto in pedido.productos)
        for pedido in pedidos_completados
    ) if pedidos_completados else 0.0

    pedidos_pendientes = Pedido.query.filter_by(estado='pendiente').count()
    umbral_stock = int(Configuracion.query.filter_by(clave='umbral_stock').first().valor) if Configuracion.query.filter_by(clave='umbral_stock').first() else 5
    alertas_stock = Producto.query.filter(Producto.stock < umbral_stock).count()
    fecha_ultimos_30_dias = datetime.now(timezone.utc) - timedelta(days=30)
    clientes_nuevos = Cliente.query.filter(Cliente.fecha_registro >= fecha_ultimos_30_dias).count()

    from sqlalchemy import func
    # Productos más vendidos
    productos_mas_vendidos_query = (
        db.session.query(
            Producto.nombre,
            Producto.precio,
            func.sum(PedidoProducto.cantidad).label('total_vendido'),
            func.sum(PedidoProducto.cantidad * Producto.precio).label('ingreso_total')
        )
        .join(PedidoProducto, Producto.id == PedidoProducto.producto_id)
        .join(Pedido, PedidoProducto.pedido_id == Pedido.id)
        .filter(Pedido.estado == 'completado')
        .group_by(Producto.id, Producto.nombre, Producto.precio)
        .order_by(func.sum(PedidoProducto.cantidad).desc())
        .limit(5)
        .all()
    )
    productos_mas_vendidos = [
        {
            'nombre': row.nombre,
            'precio': float(row.precio) if row.precio else 0.0,
            'total_vendido': int(row.total_vendido) if row.total_vendido else 0,
            'ingreso_total': float(row.ingreso_total) if row.ingreso_total else 0.0
        }
        for row in productos_mas_vendidos_query
    ] if productos_mas_vendidos_query else []

    # Pedidos por estado
    pedidos_por_estado_query = (
        db.session.query(
            Pedido.estado,
            func.count(Pedido.id).label('total')
        )
        .group_by(Pedido.estado)
        .all()
    )
    pedidos_por_estado = {estado: int(total) for estado, total in pedidos_por_estado_query} if pedidos_por_estado_query else {}

    # Ingresos por mes
    ingresos_por_mes = []
    fecha_actual = datetime.now(timezone.utc)
    for i in range(6):
        mes_inicio = (fecha_actual - relativedelta(months=i)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        mes_fin = mes_inicio + relativedelta(months=1) - timedelta(seconds=1)
        pedidos_mes = Pedido.query.filter(
            Pedido.estado == 'completado',
            Pedido.fecha >= mes_inicio,
            Pedido.fecha <= mes_fin
        ).all()
        ingreso_mes = sum(
            sum(pedido_producto.producto.precio * pedido_producto.cantidad for pedido_producto in pedido.productos)
            for pedido in pedidos_mes
        ) if pedidos_mes else 0.0
        ingresos_por_mes.append({
            'mes': mes_inicio.strftime('%B %Y'),
            'ingreso': float(ingreso_mes)
        })

    # Clientes nuevos por mes (últimos 6 meses)
    clientes_nuevos_por_mes = []
    for i in range(6):
        mes_inicio = (fecha_actual - relativedelta(months=i)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        mes_fin = mes_inicio + relativedelta(months=1) - timedelta(seconds=1)
        clientes_mes = Cliente.query.filter(
            Cliente.fecha_registro >= mes_inicio,
            Cliente.fecha_registro <= mes_fin
        ).count()
        clientes_nuevos_por_mes.append({
            'mes': mes_inicio.strftime('%B %Y'),
            'clientes': int(clientes_mes)
        })

    # Alertas de stock por producto
    productos_bajo_stock = Producto.query.filter(Producto.stock < umbral_stock).all()
    alertas_stock_por_producto = [
        {
            'nombre': producto.nombre,
            'stock': int(producto.stock),
            'umbral': int(umbral_stock)
        }
        for producto in productos_bajo_stock
    ] if productos_bajo_stock else []

    return render_template('index.html', 
                         total_ventas=total_ventas, 
                         pedidos_pendientes=pedidos_pendientes, 
                         alertas_stock=alertas_stock, 
                         clientes_nuevos=clientes_nuevos,
                         productos_mas_vendidos=productos_mas_vendidos,
                         pedidos_por_estado=pedidos_por_estado,
                         ingresos_por_mes=ingresos_por_mes,
                         clientes_nuevos_por_mes=clientes_nuevos_por_mes,
                         alertas_stock_por_producto=alertas_stock_por_producto)


@app.route('/clientes', methods=['GET', 'POST'])
@login_required
def clientes():
    cliente_a_editar = None
    form_data = None

    nombre_search = request.args.get('nombre', '').strip()
    email_search = request.args.get('email', '').strip()

    query = Cliente.query
    if nombre_search:
        query = query.filter(Cliente.nombre.ilike(f'%{nombre_search}%'))
    if email_search:
        query = query.filter(Cliente.email.ilike(f'%{email_search}%'))

    clientes = query.all()

    if request.method == 'POST':
        cliente_id = request.form.get('cliente_id')
        nombre = request.form.get('nombre')
        email = request.form.get('email')
        telefono = request.form.get('telefono')
        direccion = request.form.get('direccion')

        form_data = {
            'nombre': nombre,
            'email': email,
            'telefono': telefono,
            'direccion': direccion
        }

        cliente_existente = Cliente.query.filter_by(email=email).first()
        if cliente_id:
            cliente = Cliente.query.get_or_404(int(cliente_id))
            if cliente_existente and cliente_existente.id != cliente.id:
                flash("El email ya está registrado.", "danger")
                return render_template('clientes.html', clientes=clientes, cliente_a_editar=cliente, form_data=form_data)
            cliente.nombre = nombre
            cliente.email = email
            cliente.telefono = telefono
            cliente.direccion = direccion
            db.session.commit()
            flash("Cliente actualizado exitosamente.", "success")
        else:
            if cliente_existente:
                flash("El email ya está registrado.", "danger")
                return render_template('clientes.html', clientes=clientes, cliente_a_editar=None, form_data=form_data)
            nuevo_cliente = Cliente(
                nombre=nombre,
                email=email,
                telefono=telefono,
                direccion=direccion
            )
            db.session.add(nuevo_cliente)
            db.session.commit()
            flash("Cliente creado exitosamente.", "success")

        return redirect(url_for('clientes'))

    cliente_id = request.args.get('editar')
    if cliente_id:
        cliente_a_editar = Cliente.query.get_or_404(int(cliente_id))

    return render_template('clientes.html', clientes=clientes, cliente_a_editar=cliente_a_editar, form_data=form_data)

@app.route('/eliminar_cliente/<int:id>')
@login_required
@admin_required
def eliminar_cliente(id):
    cliente = Cliente.query.get_or_404(id)
    db.session.delete(cliente)
    db.session.commit()
    flash("Cliente eliminado exitosamente.", "success")
    return redirect(url_for('clientes'))

#********************************************************************

@app.route('/productos', methods=['GET', 'POST'])
@login_required
def productos():
    productos = Producto.query.all()
    producto_a_editar = None
    form_data = None

    if request.method == 'POST':
        producto_id = request.form.get('producto_id')
        nombre = request.form.get('nombre')
        descripcion = request.form.get('descripcion', '')  # Agregamos descripción
        precio = request.form.get('precio')
        stock = request.form.get('stock')

        form_data = {
            'nombre': nombre,
            'descripcion': descripcion,
            'precio': precio,
            'stock': stock
        }

        try:
            precio = float(precio)
            if precio < 0:
                raise ValueError("El precio no puede ser negativo.")
            stock = int(stock)
            if stock < 0:
                raise ValueError("El stock no puede ser negativo.")
        except (ValueError, TypeError) as e:
            flash("El precio y el stock deben ser valores numéricos válidos y no negativos.", "danger")
            return render_template('productos.html', productos=productos, producto_a_editar=None, form_data=form_data)

        producto_existente = Producto.query.filter_by(nombre=nombre).first()
        if producto_id:  # Modo edición
            producto = Producto.query.get_or_404(int(producto_id))
            if producto_existente and producto_existente.id != producto.id:
                flash("El nombre del producto ya está registrado.", "danger")
                return render_template('productos.html', productos=productos, producto_a_editar=producto, form_data=form_data)
            # Actualizar el inventario si el stock cambió
            inventario = Inventario.query.filter_by(producto_id=producto.id).first()
            if inventario:
                diferencia = stock - producto.stock
                inventario.cantidad += diferencia
                inventario.fecha_actualizacion = datetime.now()
                if diferencia != 0:
                    tipo_movimiento = "entrada" if diferencia > 0 else "salida"
                    movimiento = MovimientoInventario(
                        producto_id=producto.id,
                        tipo_movimiento=tipo_movimiento,
                        cantidad=abs(diferencia),
                        usuario_id=current_user.id
                    )
                    db.session.add(movimiento)
            producto.nombre = nombre
            producto.descripcion = descripcion
            producto.precio = precio
            producto.stock = stock
            db.session.commit()
            flash("Producto actualizado exitosamente.", "success")
        else:  # Modo creación
            if producto_existente:
                flash("El nombre del producto ya está registrado.", "danger")
                return render_template('productos.html', productos=productos, producto_a_editar=None, form_data=form_data)
            nuevo_producto = Producto(
                nombre=nombre,
                descripcion=descripcion,
                precio=precio,
                stock=stock
            )
            db.session.add(nuevo_producto)
            db.session.flush()  # Flush para obtener el ID del producto antes de commit
            # Crear registro en inventario
            nuevo_inventario = Inventario(
                producto_id=nuevo_producto.id,
                cantidad=stock,
                fecha_actualizacion=datetime.now()
            )
            # Registrar movimiento inicial
            movimiento = MovimientoInventario(
                producto_id=nuevo_producto.id,
                tipo_movimiento="entrada",
                cantidad=stock,
                usuario_id=current_user.id
            )
            db.session.add(nuevo_inventario)
            db.session.add(movimiento)
            db.session.commit()
            flash("Producto creado y agregado al inventario exitosamente.", "success")

        return redirect(url_for('productos'))

    producto_id = request.args.get('editar')
    if producto_id:
        producto_a_editar = Producto.query.get_or_404(int(producto_id))

    return render_template('productos.html', productos=productos, producto_a_editar=producto_a_editar, form_data=form_data)

#********************************************************************

@app.route('/eliminar_producto/<int:id>')
@login_required
@admin_required
def eliminar_producto(id):
    producto = Producto.query.get_or_404(id)
    if producto.pedidos:
        flash("No se puede eliminar el producto porque está asociado a uno o más pedidos.", "danger")
        return redirect(url_for('productos'))
    db.session.delete(producto)
    db.session.commit()
    flash("Producto eliminado exitosamente.", "success")
    return redirect(url_for('productos'))

#********************************************************************

from datetime import datetime

@app.route('/configuracion', methods=['GET', 'POST'])
@login_required
@admin_required
def configuracion():
    if request.method == 'POST':
        umbral_stock = request.form.get('umbral_stock')
        dias_retencion = request.form.get('dias_retencion_movimientos')
        moneda = request.form.get('moneda')
        tasa_iva = request.form.get('tasa_iva')
        dias_pendientes = request.form.get('dias_pendientes')

        # Lista de configuraciones a actualizar
        configuraciones = [
            ('umbral_stock', umbral_stock),
            ('dias_retencion_movimientos', dias_retencion),
            ('moneda', moneda),
            ('tasa_iva', tasa_iva),
            ('dias_pendientes', dias_pendientes)
        ]

        for clave, valor_nuevo in configuraciones:
            config = Configuracion.query.filter_by(clave=clave).first()
            if config:
                if config.valor != valor_nuevo:
                    # Registrar cambio en el historial
                    cambio = HistorialConfiguracion(
                        clave=clave,
                        valor_anterior=config.valor,
                        valor_nuevo=valor_nuevo,
                        usuario_id=current_user.id,
                        fecha=datetime.now()
                    )
                    db.session.add(cambio)
                    config.valor = valor_nuevo
            else:
                config = Configuracion(clave=clave, valor=valor_nuevo)
                db.session.add(config)
                cambio = HistorialConfiguracion(
                    clave=clave,
                    valor_anterior=None,
                    valor_nuevo=valor_nuevo,
                    usuario_id=current_user.id,
                    fecha=datetime.now()
                )
                db.session.add(cambio)

        db.session.commit()
        flash("Configuración actualizada exitosamente.", "success")
        return redirect(url_for('configuracion'))

    # Obtener valores actuales
    umbral_stock = Configuracion.query.filter_by(clave='umbral_stock').first()
    umbral_stock = int(umbral_stock.valor) if umbral_stock and umbral_stock.valor.isdigit() else 10

    dias_retencion = Configuracion.query.filter_by(clave='dias_retencion_movimientos').first()
    dias_retencion = dias_retencion.valor if dias_retencion else '30'
    
    moneda = Configuracion.query.filter_by(clave='moneda').first()
    moneda = moneda.valor if moneda else 'USD'
    
    tasa_iva = Configuracion.query.filter_by(clave='tasa_iva').first()
    tasa_iva = tasa_iva.valor if tasa_iva else '19'
    
    dias_pendientes = Configuracion.query.filter_by(clave='dias_pendientes').first()
    dias_pendientes = dias_pendientes.valor if dias_pendientes else '7'

    # Obtener historial de cambios
    historial = HistorialConfiguracion.query.order_by(HistorialConfiguracion.fecha.desc()).all()

    # Obtener productos con stock bajo
    productos_bajo_stock = Producto.query.filter(Producto.stock < umbral_stock).all()

    return render_template(
        'configuracion.html',
        umbral_stock=umbral_stock,
        dias_retencion=dias_retencion,
        moneda=moneda,
        tasa_iva=tasa_iva,
        dias_pendientes=dias_pendientes,
        historial=historial,
        productos_bajo_stock=productos_bajo_stock
    )

#**********************************************************************************

class MovimientoInventario(db.Model):
    __tablename__ = 'movimientos_inventario'
    id = db.Column(db.Integer, primary_key=True)
    producto_id = db.Column(db.Integer, db.ForeignKey('productos.id'), nullable=False)
    tipo_movimiento = db.Column(db.String(20), nullable=False)  # "entrada" o "salida"
    cantidad = db.Column(db.Integer, nullable=False)
    fecha = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    producto = db.relationship('Producto', backref='movimientos')
    usuario = db.relationship('Usuario', backref='movimientos')

#**********************************************************************************

@app.route('/inventario', methods=['GET', 'POST'])
@login_required
def inventario():
    inventarios = Inventario.query.all()
    productos = Producto.query.all()
    form = InventarioForm()
    # Configurar las opciones del campo producto_id
    form.producto_id.choices = [(producto.id, producto.nombre) for producto in productos]
    form.producto_id.choices.insert(0, (0, "Seleccione un producto"))

    inventario_a_editar = None

    if form.validate_on_submit():
        producto_id = form.producto_id.data
        cantidad = form.cantidad.data

        if producto_id == 0:
            flash("Debe seleccionar un producto válido.", "danger")
            return render_template('inventario.html', inventarios=inventarios, productos=productos, form=form, inventario_a_editar=None)

        producto = Producto.query.get(producto_id)
        if not producto:
            flash("El producto seleccionado no es válido.", "danger")
            return render_template('inventario.html', inventarios=inventarios, productos=productos, form=form, inventario_a_editar=None)

        inventario_id = request.form.get('inventario_id')
        if inventario_id:  # Modo edición
            inventario = Inventario.query.get_or_404(int(inventario_id))
            cantidad_anterior = inventario.cantidad
            producto.stock -= inventario.cantidad
            inventario.producto_id = producto_id
            inventario.cantidad = cantidad
            inventario.fecha_actualizacion = datetime.now()
            producto.stock += cantidad
            umbral = int(Configuracion.query.filter_by(clave='umbral_stock').first().valor) if Configuracion.query.filter_by(clave='umbral_stock').first() else 10
        if producto.stock < umbral:
            flash(f"Advertencia: El stock del producto {producto.nombre} está por debajo del umbral mínimo de {umbral} unidades (actual: {producto.stock}). Revise la alerta en la parte superior.", "warning")
            # Registrar el movimiento
            diferencia = cantidad - cantidad_anterior
            if diferencia != 0:
                tipo_movimiento = "entrada" if diferencia > 0 else "salida"
                movimiento = MovimientoInventario(
                    producto_id=producto_id,
                    tipo_movimiento=tipo_movimiento,
                    cantidad=abs(diferencia),
                    usuario_id=current_user.id
                )
                db.session.add(movimiento)
                print(f"Movimiento registrado (edición): {tipo_movimiento} de {abs(diferencia)} unidades para producto {producto_id}")
            db.session.commit()
            flash("Registro de inventario actualizado exitosamente.", "success")
        else:  # Modo creación
            # Verificar si ya existe un registro para este producto
            inventario_existente = Inventario.query.filter_by(producto_id=producto_id).first()
            if inventario_existente:
                # Sumar la cantidad al registro existente
                inventario_existente.cantidad += cantidad
                inventario_existente.fecha_actualizacion = datetime.now()
                producto.stock += cantidad
                umbral = int(Configuracion.query.filter_by(clave='umbral_stock').first().valor) if Configuracion.query.filter_by(clave='umbral_stock').first() else 10
            if producto.stock < umbral:
                flash(f"Advertencia: El stock del producto {producto.nombre} está por debajo del umbral mínimo de {umbral} unidades (actual: {producto.stock}). Revise la alerta en la parte superior.", "warning")

                # Registrar el movimiento
                movimiento = MovimientoInventario(
                    producto_id=producto_id,
                    tipo_movimiento="entrada",
                    cantidad=cantidad,
                    usuario_id=current_user.id
                )
                db.session.add(movimiento)
                print(f"Movimiento registrado (suma): entrada de {cantidad} unidades para producto {producto_id}")
                db.session.commit()
                flash("Cantidad sumada al registro de inventario existente.", "success")
            else:
                # Crear un nuevo registro si no existe
                nuevo_inventario = Inventario(
                    producto_id=producto_id,
                    cantidad=cantidad,
                    fecha_actualizacion=datetime.now()
                )
                producto.stock += cantidad
                umbral = int(Configuracion.query.filter_by(clave='umbral_stock').first().valor) if Configuracion.query.filter_by(clave='umbral_stock').first() else 10
            if producto.stock < umbral:
                flash(f"Advertencia: El stock del producto {producto.nombre} está por debajo del umbral mínimo de {umbral} unidades (actual: {producto.stock}). Revise la alerta en la parte superior.", "warning")

                # Registrar el movimiento
                movimiento = MovimientoInventario(
                    producto_id=producto_id,
                    tipo_movimiento="entrada",
                    cantidad=cantidad,
                    usuario_id=current_user.id
                )
                db.session.add(movimiento)
                print(f"Movimiento registrado (creación): entrada de {cantidad} unidades para producto {producto_id}")
                db.session.add(nuevo_inventario)
                db.session.commit()
                flash("Registro de inventario creado exitosamente.", "success")

        return redirect(url_for('inventario'))

    inventario_id = request.args.get('editar')
    if inventario_id:
        inventario_a_editar = Inventario.query.get_or_404(int(inventario_id))
        form.producto_id.data = inventario_a_editar.producto_id
        form.cantidad.data = inventario_a_editar.cantidad

    umbral_config = Configuracion.query.filter_by(clave='umbral_stock').first()
    umbral_stock = int(umbral_config.valor) if umbral_config else 10
    return render_template('inventario.html', inventarios=inventarios, productos=productos, form=form, inventario_a_editar=inventario_a_editar, configuracion={'umbral_stock': umbral_stock})

#**********************************************************************************

@app.route('/eliminar_inventario/<int:id>')
@login_required
@admin_required
def eliminar_inventario(id):
    inventario = Inventario.query.get_or_404(id)
    producto = inventario.producto
    cantidad_eliminada = inventario.cantidad
    producto.stock -= inventario.cantidad
    umbral = int(Configuracion.query.filter_by(clave='umbral_stock').first().valor) if Configuracion.query.filter_by(clave='umbral_stock').first() else 10
    if producto.stock < umbral:
        flash(f"Advertencia: El stock del producto {producto.nombre} está por debajo del umbral mínimo de {umbral} unidades (actual: {producto.stock}). Revise la alerta en la parte superior.", "warning")

    # Registrar el movimiento
    movimiento = MovimientoInventario(
        producto_id=inventario.producto_id,
        tipo_movimiento="salida",
        cantidad=cantidad_eliminada,
        usuario_id=current_user.id
    )
    db.session.add(movimiento)
    print(f"Movimiento registrado (eliminación): salida de {cantidad_eliminada} unidades para producto {inventario.producto_id}")
    db.session.delete(inventario)
    db.session.commit()
    flash("Registro de inventario eliminado exitosamente.", "success")
    return redirect(url_for('inventario'))

#************************************************************************************

@app.route('/pedidos', methods=['GET', 'POST'])
@login_required
def pedidos():
    clientes = Cliente.query.all()
    productos = Producto.query.all()
    pedido_a_editar = None
    form_data = None

    cliente_id_search = request.args.get('cliente_id', '')
    fecha_search = request.args.get('fecha', '')
    estado_search = request.args.get('estado', '')
    page = request.args.get('page', 1, type=int)

    query = Pedido.query
    if cliente_id_search:
        query = query.filter_by(cliente_id=cliente_id_search)
    if fecha_search:
        try:
            fecha = datetime.strptime(fecha_search, '%Y-%m-%d')
            query = query.filter_by(fecha=fecha)
        except ValueError:
            flash("La fecha de búsqueda no es válida. Use el formato YYYY-MM-DD.", "danger")
    if estado_search:
        query = query.filter_by(estado=estado_search)

    per_page = 10
    paginacion = query.paginate(page=page, per_page=per_page, error_out=False)
    pedidos = paginacion.items

    if request.method == 'POST':
        pedido_id = request.form.get('pedido_id')
        cliente_id = request.form.get('cliente_id')
        fecha = request.form.get('fecha')
        estado = request.form.get('estado')
        producto_ids = request.form.getlist('producto_ids[]')
        cantidades = request.form.getlist('cantidades[]')

        form_data = {
            'cliente_id': cliente_id,
            'fecha': fecha,
            'estado': estado,
            'productos': list(zip(producto_ids, cantidades))
        }

        cliente = Cliente.query.get(cliente_id)
        if not cliente:
            flash("El cliente seleccionado no es válido.", "danger")
            return render_template('pedidos.html', pedidos=pedidos, clientes=clientes, productos=productos, pedido_a_editar=None, form_data=form_data, paginacion=paginacion)

        try:
            fecha = datetime.strptime(fecha, '%Y-%m-%d')
        except ValueError:
            flash("La fecha no es válida. Use el formato YYYY-MM-DD.", "danger")
            return render_template('pedidos.html', pedidos=pedidos, clientes=clientes, productos=productos, pedido_a_editar=None, form_data=form_data, paginacion=paginacion)

        if not producto_ids or not cantidades or len(producto_ids) != len(cantidades):
            flash("Debe seleccionar al menos un producto y especificar cantidades válidas.", "danger")
            return render_template('pedidos.html', pedidos=pedidos, clientes=clientes, productos=productos, pedido_a_editar=None, form_data=form_data, paginacion=paginacion)

        productos_consolidados = {}
        for producto_id, cantidad in zip(producto_ids, cantidades):
            try:
                cantidad = int(cantidad)
                if cantidad <= 0:
                    raise ValueError("La cantidad debe ser mayor que 0.")
            except (ValueError, TypeError):
                flash("Las cantidades deben ser números enteros mayores que 0.", "danger")
                return render_template('pedidos.html', pedidos=pedidos, clientes=clientes, productos=productos, pedido_a_editar=None, form_data=form_data, paginacion=paginacion)

            producto = Producto.query.get(producto_id)
            if not producto:
                flash("Uno de los productos seleccionados no es válido.", "danger")
                return render_template('pedidos.html', pedidos=pedidos, clientes=clientes, productos=productos, pedido_a_editar=None, form_data=form_data, paginacion=paginacion)

            if producto_id in productos_consolidados:
                productos_consolidados[producto_id]['cantidad'] += cantidad
            else:
                productos_consolidados[producto_id] = {'producto': producto, 'cantidad': cantidad}

            if producto.stock < productos_consolidados[producto_id]['cantidad']:
                flash(f"No hay suficiente stock para el producto {producto.nombre}. Stock disponible: {producto.stock}.", "danger")
                return render_template('pedidos.html', pedidos=pedidos, clientes=clientes, productos=productos, pedido_a_editar=None, form_data=form_data, paginacion=paginacion)

        productos_asociados = [(item['producto'], item['cantidad']) for item in productos_consolidados.values()]

        if pedido_id:
            pedido = Pedido.query.get_or_404(int(pedido_id))
            for pedido_producto in pedido.productos:
                pedido_producto.producto.stock += pedido_producto.cantidad
            for pedido_producto in pedido.productos:
                db.session.delete(pedido_producto)
            pedido.productos = []

            pedido.cliente_id = cliente_id
            pedido.fecha = fecha
            pedido.estado = estado
            for producto, cantidad in productos_asociados:
                pedido.productos.append(PedidoProducto(producto=producto, cantidad=cantidad))
                producto.stock -= cantidad
                # Registrar movimiento en inventario
                inventario = Inventario.query.filter_by(producto_id=producto.id).first()
                if inventario:
                    inventario.cantidad -= cantidad
                    inventario.fecha_actualizacion = datetime.now()
                    movimiento = MovimientoInventario(
                        producto_id=producto.id,
                        tipo_movimiento="salida",
                        cantidad=cantidad,
                        usuario_id=current_user.id
                    )
                    db.session.add(movimiento)
                # Verificar si el stock cae por debajo del umbral
                umbral = int(Configuracion.query.filter_by(clave='umbral_stock').first().valor)
                if producto.stock < umbral:
                    flash(f"Alerta: El stock del producto {producto.nombre} ha caído por debajo del umbral ({producto.stock} unidades).", "warning")
            db.session.commit()
            flash("Pedido actualizado exitosamente.", "success")
        else:
            nuevo_pedido = Pedido(
                cliente_id=cliente_id,
                fecha=fecha,
                estado=estado
            )
            for producto, cantidad in productos_asociados:
                nuevo_pedido.productos.append(PedidoProducto(producto=producto, cantidad=cantidad))
                producto.stock -= cantidad
                # Registrar movimiento en inventario
                inventario = Inventario.query.filter_by(producto_id=producto.id).first()
                if inventario:
                    inventario.cantidad -= cantidad
                    inventario.fecha_actualizacion = datetime.now()
                    movimiento = MovimientoInventario(
                        producto_id=producto.id,
                        tipo_movimiento="salida",
                        cantidad=cantidad,
                        usuario_id=current_user.id
                    )
                    db.session.add(movimiento)
                # Verificar si el stock cae por debajo del umbral
                umbral = int(Configuracion.query.filter_by(clave='umbral_stock').first().valor)
                if producto.stock < umbral:
                    flash(f"Alerta: El stock del producto {producto.nombre} ha caído por debajo del umbral ({producto.stock} unidades).", "warning")
            db.session.add(nuevo_pedido)
            db.session.commit()
            flash("Pedido creado exitosamente.", "success")

        return redirect(url_for('pedidos'))

    pedido_id = request.args.get('editar')
    if pedido_id:
        pedido_a_editar = Pedido.query.get_or_404(int(pedido_id))

# Obtener movimientos de inventario para el pedido que se está editando
    movimientos = []
    if pedido_a_editar:
        producto_ids = [pp.producto_id for pp in pedido_a_editar.productos]
        movimientos = MovimientoInventario.query.filter(MovimientoInventario.producto_id.in_(producto_ids)).order_by(MovimientoInventario.fecha.desc()).all()

    return render_template('pedidos.html', pedidos=pedidos, clientes=clientes, productos=productos, pedido_a_editar=pedido_a_editar, form_data=form_data, paginacion=paginacion, movimientos=movimientos)


#************************************************************************   

@app.route('/eliminar_pedido/<int:id>')
@login_required
@admin_required
def eliminar_pedido(id):
    pedido = Pedido.query.get_or_404(id)
    # Restaurar el stock de los productos
    for pedido_producto in pedido.productos:
        producto = pedido_producto.producto
        cantidad = pedido_producto.cantidad
        producto.stock += cantidad  # Restaurar stock en productos
        # Actualizar inventario
        inventario = Inventario.query.filter_by(producto_id=producto.id).first()
        if inventario:
            inventario.cantidad += cantidad
            inventario.fecha_actualizacion = datetime.now()
            # Registrar movimiento de entrada
            movimiento = MovimientoInventario(
                producto_id=producto.id,
                tipo_movimiento="entrada",
                cantidad=cantidad,
                usuario_id=current_user.id
            )
            db.session.add(movimiento)
    db.session.delete(pedido)
    db.session.commit()
    flash("Pedido eliminado y stock restaurado exitosamente.", "success")
    return redirect(url_for('pedidos'))

#*************************************************************************

@app.route('/usuarios', methods=['GET', 'POST'])
@login_required
@admin_required
def usuarios():
    usuarios = Usuario.query.all()
    usuario_a_editar = None
    form_data = None

    if request.method == 'POST':
        usuario_id = request.form.get('usuario_id')
        nombre = request.form.get('nombre')
        email = request.form.get('email')
        password = request.form.get('password')  # Cambia 'contraseña' a 'password'
        rol = request.form.get('rol')

        form_data = {
            'nombre': nombre,
            'email': email,
            'contraseña': password,  # Cambia 'contraseña' a 'password'
            'rol': rol
        }

        usuario_existente = Usuario.query.filter_by(email=email).first()
        if not password or len(password) < 6:
            flash("La contraseña debe tener al menos 6 caracteres.", "danger")
            return render_template('usuarios.html', usuarios=usuarios, usuario_a_editar=None, form_data=form_data)

        if usuario_id:
            usuario = Usuario.query.get_or_404(int(usuario_id))
            if usuario_existente and usuario_existente.id != usuario.id:
                flash("El email ya está registrado.", "danger")
                return render_template('usuarios.html', usuarios=usuarios, usuario_a_editar=usuario, form_data=form_data)
            usuario.nombre = nombre
            usuario.email = email
            usuario.set_password(password)
            usuario.rol = rol
            db.session.commit()
            flash("Usuario actualizado exitosamente.", "success")
        else:
            if usuario_existente:
                flash("El email ya está registrado.", "danger")
                return render_template('usuarios.html', usuarios=usuarios, usuario_a_editar=None, form_data=form_data)
            nuevo_usuario = Usuario(nombre=nombre, email=email, rol=rol)
            nuevo_usuario.set_password(password)
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash("Usuario creado exitosamente.", "success")

        return redirect(url_for('usuarios'))

    usuario_id = request.args.get('editar')
    if usuario_id:
        usuario_a_editar = Usuario.query.get_or_404(int(usuario_id))

    return render_template('usuarios.html', usuarios=usuarios, usuario_a_editar=usuario_a_editar, form_data=form_data)

@app.route('/eliminar_usuario/<int:id>')
@login_required
@admin_required
def eliminar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    db.session.delete(usuario)
    db.session.commit()
    flash("Usuario eliminado exitosamente.", "success")
    return redirect(url_for('usuarios'))

# Crear las tablas y agregar datos de prueba
with app.app_context():
    try:
        print("Intentando conectar a la base de datos...")
        db.session.execute(text("SELECT 1"))
        print("Conexión a la base de datos exitosa.")
        print("Creando tablas...")
        db.create_all()
        print("Tablas creadas exitosamente.")
        print("Agregando datos de prueba...")
        agregar_datos_prueba()
        print("Datos de prueba agregados exitosamente.")
    except Exception as e:
        print(f"Error al crear las tablas o agregar datos: {e}")

# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(debug=True)