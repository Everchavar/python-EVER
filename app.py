from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask_mysqldb import MySQL

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'

# Configuración de MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flask_login'

mysql = MySQL(app)

# Función para agregar cabeceras de no caché
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"    # Deshabilita la caché
    response.headers["Pragma"] = "no-cache"    # Compatibilidad con HTTP/1.0
    response.headers["Expires"] = "0"    # Fecha de expiración en el pasado
    return response

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('home'))    # Redirige a home si está autenticado
    return redirect(url_for('login'))    # Redirige a login si no está autenticado

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        # La contraseña no es necesaria para este bypass, pero la capturamos
        password = request.form['password'] 

        cur = mysql.connection.cursor()

        # ESTE ES EL PUNTO VULNERABLE DE INYECCIÓN SQL CLÁSICA (Punto 1 del Lab)
        # Se construye la consulta pegando el string del usuario directamente.
        sql_vulnerable = f"SELECT id, username, password FROM users WHERE username = '{username}'"
        
        # Ejecutamos la consulta INSEGURA
        cur.execute(sql_vulnerable)
        user = cur.fetchone()
        cur.close()

        # Si la inyección fue exitosa (el SELECT devolvió un usuario)
        if user: 
            # Damos acceso directo sin verificar la contraseña hasheada (para la demo)
            session['username'] = user[1] 
            return redirect(url_for('home'))
        else:
            flash('Usuario o contraseña incorrectos')
            return redirect(url_for('login'))

    response = make_response(render_template('login.html'))
    return add_no_cache_headers(response)    # Aplica las cabeceras de no caché

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        # Guardamos la contraseña en texto plano (SIN ENCRIPTACIÓN)
        cur.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, password))
        mysql.connection.commit()
        cur.close()

        flash('Registro exitoso. Por favor, inicia sesión.')
        return redirect(url_for('login'))

    response = make_response(render_template('register.html'))
    return add_no_cache_headers(response)    # Aplica las cabeceras de no caché

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))    # Redirige a login si no está autenticado
    response = make_response(render_template('home.html'))
    return add_no_cache_headers(response)    # Aplica las cabeceras de no caché

# ----------------------------------------------------------------------
# INYECCIÓN SQL EN URL CON UNION (Punto 2 del Lab)
# ----------------------------------------------------------------------
@app.route('/plato_detalle')
def plato_detalle():
    # Obtiene el ID del plato desde el parámetro 'id' en la URL
    plato_id = request.args.get('id', '1')

    cur = mysql.connection.cursor()

    # ESTE ES EL PUNTO VULNERABLE: Construcción de consulta con f-string
    # La consulta espera un ID, pero puede recibir código SQL malicioso.
    try:
        sql_vulnerable_union = f"SELECT id, nombre, descripcion FROM menu WHERE id = {plato_id}"
        cur.execute(sql_vulnerable_union)
        
        # user[0] = id, user[1] = nombre, user[2] = descripcion
        plato = cur.fetchone() 
    except Exception as e:
        # Si la consulta falla (por un error de inyección), enviamos un mensaje.
        plato = (0, "ERROR DE SINTAXIS O COLUMNAS (Prueba con otro número de columnas)", str(e))
        print(f"Error de base de datos durante la inyección: {e}")
    finally:
        cur.close()

    if plato:
        response = make_response(render_template('detalle_vulnerable.html', plato=plato))
    else:
        response = make_response(render_template('detalle_vulnerable.html', plato=(0, "Plato no encontrado", "Intenta con otro ID.")))
        
    return add_no_cache_headers(response)

@app.route('/logout')
def logout():
    session.pop('username', None)
    response = make_response(redirect(url_for('login')))
    return add_no_cache_headers(response)    # Aplica las cabeceras de no caché

if __name__ == '__main__':
    app.run(debug=True)