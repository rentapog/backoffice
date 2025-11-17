# This is the Flask app for site1
from flask import Flask, render_template


app = Flask(__name__, template_folder='templates', static_folder='static')

@app.route('/')
def home():
    return render_template('index.html')

# Route for domain sales page
@app.route('/domain-sales')
def domain_sales():
    return render_template('domain_sales.html')

if __name__ == '__main__':
    app.run(debug=True)
