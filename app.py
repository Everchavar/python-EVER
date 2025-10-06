from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'

# Configuración de MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flask_login'

mysql = MySQL(app)
bcrypt = Bcrypt(app)

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
        password = request.form['password']

        # ----------------------------------------------------------------------
        # !!! INICIO DE LA VULNERABILIDAD SQL INTENCIONAL !!!
        # ----------------------------------------------------------------------
        
        # 1. Obtenemos el cursor
        cur = mysql.connection.cursor()
        
        # 2. CONSTRUCCIÓN VULNERABLE DE LA CONSULTA usando f-string.
        #    Esto permite que el código SQL inyectado se ejecute.
        #    NOTAR que se debe encerrar la variable en comillas simples en el SQL:
        sql_vulnerable = f"SELECT * FROM users WHERE username = '{username}'"

        # 3. Ejecutamos la consulta. Aquí, la inyección es posible.
        cur.execute(sql_vulnerable)
        
        # ----------------------------------------------------------------------
        # !!! FIN DE LA VULNERABILIDAD SQL INTENCIONAL !!!
        # ----------------------------------------------------------------------
        
        user = cur.fetchone()
        cur.close()

        # Si encontramos un usuario (gracias a la inyección o credenciales válidas)
        if user:
            # NOTA: En la inyección, 'user' será el primer usuario de la DB.
            # La verificación de la contraseña aún se hace contra el hash de ese usuario.

            # Si el atacante usa una inyección que omite la contraseña (clásica):
            # En este escenario, si el atacante ingresa: ' OR '1'='1
            # La consulta devuelve el primer usuario, PERO luego verifica la contraseña 
            # de ese usuario (user[2]) contra el 'password' ingresado.
            
            # Para una demostración de bypass MÁS SIMPLE, eliminemos la verificación 
            # de contraseña si la consulta vulnerable devuelve un usuario:
            
            # ELIMINANDO la verificación de contraseña para DEMOSTRACIÓN FÁCIL:
            # if user and bcrypt.check_password_hash(user[2], password): 
            
            # Reemplazamos por un simple if user (lo que la inyección hace):
            
            # Si el objetivo es solo demostrar el BYPASS, puedes simplificar la lógica
            # para que cualquier cosa que devuelva la consulta vulnerable te dé acceso.
            
            # Opción 1 (Inyección Bypass Total):
            session['username'] = user[1] # user[1] es el username
            return redirect(url_for('home'))

        else:
            flash('Usuario o contraseña incorrectos (SQLi Proof)')
            return redirect(url_for('login'))

    response = make_response(render_template('login.html'))
    return add_no_cache_headers(response)    # Aplica las cabeceras de no caché

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        cur = mysql.connection.cursor()
        cur.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
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

@app.route('/logout')
def logout():
    session.pop('username', None)
    response = make_response(redirect(url_for('login')))
    return add_no_cache_headers(response)    # Aplica las cabeceras de no caché

if __name__ == '__main__':
    app.run(debug=True)