import csv
import sqlite3

def generate_stock_report():
    # Connect to the database
    conn = sqlite3.connect('easystock.db')  # Assuming SQLite database
    cursor = conn.cursor()
    
    # Query to fetch product and stock details
    cursor.execute("""
        SELECT ProductID, Name, StockLevel, Price 
        FROM Products
    """)
    products = cursor.fetchall()
     

    # Create a CSV file
    with open('stock_report.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        # Writing the header
        writer.writerow(['ProductID', 'Product Name', 'Stock Level', 'Price'])
        
        # Write product details to CSV
        for product in products:
            writer.writerow(product)
    
    print("Stock report generated successfully!")

# Call the function
generate_stock_report()

