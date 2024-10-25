from flask import Flask, request, jsonify
from models import Product, db

app = Flask(__name__)

@app.route('/products', methods=['POST'])
def add_product():
    data = request.get_json()
    new_product = Product(
        name=data['name'],
        description=data['description'],
        price=data['price'],
        quantity_in_stock=data['quantity_in_stock'],
        reorder_level=data['reorder_level']
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product added successfully'}), 201
