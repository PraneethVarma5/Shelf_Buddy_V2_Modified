from xml.parsers.expat import errors
from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, url_for, Response
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import requests
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
load_dotenv()

def get_db_connection():
    conn = sqlite3.connect("shelfbuddy.db")
    conn.row_factory = sqlite3.Row
    return conn


app = Flask(__name__)

def create_tables():
    conn = get_db_connection()
    cur = conn.cursor()

    # PRODUCTS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        category TEXT NOT NULL,
        shelf_life_room_closed INTEGER,
        shelf_life_room_opened INTEGER,
        shelf_life_refrigerated_closed INTEGER,
        shelf_life_refrigerated_opened INTEGER,
        shelf_life_frozen_closed INTEGER,
        shelf_life_frozen_opened INTEGER
    )
    """)

    # USERS
    cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
)
""")

    # PANTRY
    cur.execute("""
    CREATE TABLE IF NOT EXISTS pantry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        product TEXT,
        expiry_date TEXT,
        UNIQUE(user_id, product, expiry_date),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # SUGGESTIONS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS suggestions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT,
        message TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

app.secret_key = "super_secret_key"

CORS(app)


def get_shelf_life(product, storage, opened):
    storage_map = {
        'room': 'room',
        'refrigerated': 'refrigerated',
        'frozen': 'frozen'
    }

    mapped_storage = storage_map.get(storage, 'room')
    column = f"shelf_life_{mapped_storage}_{'opened' if opened else 'closed'}"
    
    conn = get_db_connection()
    cur = conn.cursor()

    query = f"""
        SELECT {column}
        FROM products
        WHERE LOWER(name) LIKE ?
    """

    search_term = f"%{product.lower()}%"
    cur.execute(query, (search_term,))
    result = cur.fetchone()

    cur.close()
    conn.close()

    return result[0] if result and result[0] is not None else None

#Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, password)
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            flash("User already exists. Try logging in instead.", "error")
            return render_template("register.html")
        finally:
            cur.close()
            conn.close()

        return redirect(url_for('login'))

    return render_template("register.html")

#login route
from flask import flash

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role FROM users WHERE email=?", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            flash("User not found. Please register.", "error")
            return render_template("login.html")
        from werkzeug.security import check_password_hash
        if not check_password_hash(user[2], password):
            flash("Incorrect password.", "error")
            return render_template("login.html")
    


        session['user_id'] = user[0]
        session['username'] = user[1]
        session['role'] = user[3]
        return redirect('/home')

    return render_template("login.html")

# Guest Mode route
@app.route('/guest')
def guest():
    session['guest'] = True
    session['user_id'] = None
    session['username'] = "Guest"
    return redirect(url_for('home'))


# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('first_page'))

# Save to pantry route
@app.route('/save-to-pantry', methods=['POST'])
def save_to_pantry():

    if not session.get('user_id'):
        return jsonify({"status": "error", "message": "Login required."})

    data = request.json
    product = data.get("product")
    expiry_date = data.get("expiry_date")

    if not product or not expiry_date:
        return jsonify({"status": "error", "message": "Invalid data."})

    conn = get_db_connection()
    cur = conn.cursor()

    # Prevent duplicates
    cur.execute("""
        SELECT id FROM pantry
        WHERE user_id=? AND product=? AND expiry_date=?
    """, (session['user_id'], product, expiry_date))

    existing = cur.fetchone()

    if existing:
        cur.close()
        conn.close()
        return jsonify({"status": "error", "message": "Item already saved."})

    cur.execute("""
        INSERT INTO pantry (user_id, product, expiry_date)
        VALUES (?, ?, ?)
    """, (session['user_id'], product, expiry_date))

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"status": "success", "message": "Saved to pantry!"})

# Pantry route to display saved items and their expiry dates, sorted by nearest expiry first
@app.route('/pantry')
def pantry():

    if not session.get('user_id'):
        return redirect('/login')

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, product, expiry_date
        FROM pantry
        WHERE user_id=?
        ORDER BY expiry_date ASC
    """, (session['user_id'],))

    rows = cur.fetchall()
    cur.close()
    conn.commit()
    conn.close()

    pantry_items = []
    today = datetime.now().date()

    for row in rows:
        expiry = datetime.strptime(row["expiry_date"], "%Y-%m-%d").date()
        days_left = (expiry - today).days

        pantry_items.append({
            "id": row["id"],
            "product": row["product"],
            "expiry_date": row["expiry_date"],
            "days_left": days_left
        })

    return render_template("pantry.html", items=pantry_items)

# Route to delete an item from the pantry
@app.route('/delete-from-pantry', methods=['POST'])
def delete_from_pantry():

    if not session.get('user_id'):
        return jsonify({"status": "error", "message": "Unauthorized"})

    data = request.json
    item_id = data.get("item_id")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        DELETE FROM pantry
        WHERE id=? AND user_id=?
    """, (item_id, session['user_id']))

    conn.commit()

    cur.close()
    conn.close()

    return jsonify({"status": "success"})


#pantry stats route to show number of expired and soon-to-expire items
@app.route('/pantry-stats')
def pantry_stats():
    if not session.get('user_id'):
        return jsonify({"expired":0,"soon":0,"safe":0,"total":0})

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT expiry_date FROM pantry
        WHERE user_id = ?
    """, (session['user_id'],))

    rows = cur.fetchall()
    cur.close()
    conn.close()

    expired = soon = safe = 0
    today = datetime.now().date()
    
    for (expiry_date,) in rows:
        expiry = datetime.strptime(expiry_date, "%Y-%m-%d").date()
        days = (expiry - today).days
        if days < 0:
            expired += 1
        elif days <= 3:
            soon += 1
        else:
            safe += 1

    return jsonify({
        "expired": expired,
        "soon": soon,
        "safe": safe,
        "total": expired + soon + safe
    })



# Route for robots.txt
@app.route('/robots.txt')
def serve_robots():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'robots.txt',
        mimetype='text/plain'
    )

# Route for sitemap.xml
@app.route('/sitemap.xml')
def sitemap_xml():
    return send_from_directory(app.static_folder, 'sitemap.xml')

@app.route('/get-product', methods=['POST'])
def get_product():
    data = request.json
    product = data.get('product', '').strip()
    storage = data.get('storage', 'room')
    opened = data.get('opened', False)
    manu_date = data.get('manufacturing_date')

    if not product:
        return jsonify({'status': 'error', 'message': 'Product name is required'}), 400

    shelf_life = get_shelf_life(product, storage, opened)
    if shelf_life is None:
        return jsonify({'status': 'error', 'message': 'Product not found or shelf life missing'}), 404

    if manu_date:
        try:
            if manu_date == "Invalid Date" or manu_date.strip() == "":
                raise ValueError
            mdate = datetime.strptime(manu_date, '%Y-%m-%d')
            expiry = mdate + timedelta(days=shelf_life)
            return jsonify({
                'status': 'success',
                'expiry_date': expiry.strftime('%Y-%m-%d'),
                'shelf_life': shelf_life
            })
        except:
            return jsonify({'status': 'error', 'message': 'Invalid date'}), 400

    return jsonify({
        'status': 'success',
        'shelf_life': shelf_life
    })


@app.route('/get-category-average', methods=['POST'])
def get_category_average():
    data = request.json
    category = data.get('category')

    if not category:
        return jsonify({'status': 'error', 'message': 'Category is required'}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT AVG(
            shelf_life_room_closed +
            shelf_life_refrigerated_closed +
            shelf_life_frozen_closed
        ) / 3
        FROM products
        WHERE LOWER(category) = ?
    """, (category.lower(),))

    avg = cur.fetchone()[0]

    cur.close()
    conn.close()

    if avg is None:
        return jsonify({'status': 'error', 'message': 'Category not found'}), 404

    return jsonify({
        'status': 'success',
        'category': category,
        'average_shelf_life': round(avg)
    })

@app.route('/')
def first_page():
    return render_template("landing.html")

@app.route('/home')
def home():
    return render_template("main.html")

# Debug route to check users in the database
# @app.route('/debug-users')
# def debug_users():
#     conn = get_db_connection()
#     cur = conn.cursor()
#     cur.execute("SELECT id, username, email FROM users")
#     users = cur.fetchall()
#     cur.close()
#     conn.close()
#     return str(users)

@app.route('/submit-suggestion', methods=['POST'])
def submit_suggestion():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    message = data.get("message")

    if not message:
        return jsonify({"status": "error", "message": "Message required"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO suggestions (name, email, message) VALUES (?, ?, ?)",
        (name, email, message)
    )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"status": "success"})

@app.route('/suggest-recipe')
def suggest_recipe():
    return render_template("suggest_recipe.html")


@app.route('/get-recipes', methods=['POST'])
def get_recipes():

    data = request.json
    offset = data.get("offset", 0)

    ingredient1 = data.get("ingredient1")
    ingredient2 = data.get("ingredient2")
    ingredient3 = data.get("ingredient3")
    cuisine = data.get("cuisine")

    ingredients = ",".join(
        [i for i in [ingredient1, ingredient2, ingredient3] if i]
    )

    api_key = "f2a1f02ecc784581b1a119d2bb0f740a"

    url = "https://api.spoonacular.com/recipes/complexSearch"

    params = {
        "apiKey": api_key,
        "query": ingredient1,  # 🔥 THIS is important
        "number": 4,
        "offset": offset,
        "addRecipeInformation": True
    }

    # Only add these if they exist
    if ingredients:
        params["includeIngredients"] = ingredients

    if cuisine:
        params["cuisine"] = cuisine

    response = requests.get(url, params=params)

    return jsonify(response.json())

# @app.route('/debug-suggestions')
# def debug_suggestions():
#     conn = get_db_connection()
#     cur = conn.cursor()
#     cur.execute("SELECT * FROM suggestions")
#     rows = cur.fetchall()
#     conn.close()
#     return str(rows)

from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        if not session.get("user_id"):
            return redirect("/login")

        if session.get("role") != "admin":
            return "Unauthorized", 403

        return f(*args, **kwargs)

    return decorated

@app.route("/admin")
@admin_required
def admin_dashboard():

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, username, email, role FROM users")
    users = cur.fetchall()

    cur.execute("SELECT id, name, category FROM products")
    products = cur.fetchall()

    cur.execute("SELECT id, name, email, message, created_at FROM suggestions ORDER BY id DESC")
    suggestions = cur.fetchall()

    conn.close()

    return render_template(
        "admin.html",
        users=users,
        products=products,
        suggestions=suggestions
    )


if __name__ == '__main__':
    create_tables()
    port = int(os.environ.get("PORT", 10000))
    app.run(debug=True, host='0.0.0.0', port=port)
