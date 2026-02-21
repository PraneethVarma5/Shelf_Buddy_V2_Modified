from app import get_db_connection, create_tables

create_tables()
def populate_products():
    conn = get_db_connection()
    cur = conn.cursor()

    products = [
        ("Rice", "food", 180, 90, 365, 180, 0, 0),
("Basmati Rice", "food", 365, 180, 365, 180, 0, 0),
("Brown Rice", "food", 120, 60, 240, 120, 0, 0),
("Wheat Flour", "food", 180, 60, 365, 180, 730, 365),
("Maida", "food", 180, 60, 365, 180, 730, 365),
("Sugar", "food", 3650, 3650, 3650, 3650, 0, 0),
("Salt", "food", 3650, 3650, 3650, 3650, 0, 0),
("Lentils", "food", 365, 180, 365, 180, 0, 0),
("Chickpeas", "food", 730, 365, 730, 365, 0, 0),
("Rajma", "food", 730, 365, 730, 365, 0, 0),

# Oils & Fats
("Vegetable Oil", "food", 365, 180, 0, 0, 0, 0),
("Olive Oil", "food", 365, 180, 0, 0, 0, 0),
("Ghee", "food", 365, 180, 365, 180, 0, 0),
("Butter", "food", 1, 0, 180, 30, 365, 180),

# Dairy
("Milk", "food", 0, 0, 5, 3, 0, 0),
("Curd", "food", 0, 0, 14, 5, 0, 0),
("Cheese", "food", 0, 0, 180, 30, 240, 180),
("Paneer", "food", 0, 0, 5, 2, 90, 30),

# Vegetables
("Onion", "food", 30, 14, 60, 14, 0, 0),
("Potato", "food", 60, 0, 0, 0, 0, 0),
("Tomato", "food", 7, 0, 14, 7, 0, 0),
("Carrot", "food", 5, 0, 21, 10, 180, 180),
("Cabbage", "food", 3, 0, 14, 7, 0, 0),
("Spinach", "food", 1, 0, 5, 3, 180, 90),
("Capsicum", "food", 5, 0, 14, 7, 0, 0),
("Brinjal", "food", 3, 0, 7, 5, 0, 0),

# Fruits
("Apple", "food", 7, 0, 30, 15, 0, 0),
("Banana", "food", 3, 0, 7, 3, 0, 0),
("Orange", "food", 7, 0, 21, 10, 0, 0),
("Mango", "food", 3, 0, 7, 5, 180, 90),
("Grapes", "food", 2, 0, 7, 5, 0, 0),

# Meat & Fish
("Chicken", "food", 0, 0, 2, 2, 365, 180),
("Mutton", "food", 0, 0, 3, 3, 365, 180),
("Fish", "food", 0, 0, 2, 2, 240, 120),
("Eggs", "food", 7, 0, 30, 0, 0, 0),

# Packaged
("Bread", "food", 5, 5, 14, 14, 90, 30),
("Biscuits", "food", 180, 30, 0, 0, 0, 0),
("Instant Noodles", "food", 365, 365, 0, 0, 0, 0),
("Jam", "food", 365, 0, 365, 90, 0, 0),
("Honey", "food", 3650, 3650, 3650, 3650, 0, 0),
("Peanut Butter", "food", 365, 180, 365, 180, 0, 0),
("Ketchup", "food", 365, 90, 365, 90, 0, 0),
("Mayonnaise", "food", 30, 7, 90, 30, 0, 0),
]
    

    cur.executemany("""
        INSERT OR IGNORE INTO products
        (name, category,
         shelf_life_room_closed,
         shelf_life_room_opened,
         shelf_life_refrigerated_closed,
         shelf_life_refrigerated_opened,
         shelf_life_frozen_closed,
         shelf_life_frozen_opened)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, products)

    conn.commit()
    conn.close()

    print("Products inserted successfully.")

if __name__ == "__main__":
    populate_products()