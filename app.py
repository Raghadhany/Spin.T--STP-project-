from flask import Flask , render_template ,request , session ,url_for ,redirect, jsonify 
from flask_mysqldb import MySQL
import MySQLdb.cursors
import MySQLdb.cursors,re
import bcrypt

app = Flask(__name__)

#To secure sessions 
app.secret_key='spint_project_7890'
app.secret_key_hash= 'spint_project_9999'

#Database connection 
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '############'
app.config['MYSQL_DB'] = 'spintlogin'

#intializing MySQL
mysql = MySQL(app)


#bcrypt
def hash_password(password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def check_password(password, hashed_password):
    # Check if the plain password matches the hashed password
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

@app.route('/processjson', methods=['POST'])
def processjson():
    account = request.get_json()
    First_Name= account['First_Name']
    Last_Name= account['Last_Name']
    Number= account['Number']
    Password= account['Password']
    Email= account['Email']
    return jsonify({'result':'success!', First_Name:'First_Name', Last_Name: 'Last_Name',Number: 'Number',Password:'Password', Email:'Email'})

#Home page
@app.route('/')
def home():
 # Check if the user is logged in
    
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('homepage.html', Email=session['Email'])
    
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))    

#login page
@app.route('/signin',methods=['GET','POST'])
def login():
    msg=''
    if request.method == 'POST' and  'Email' in request.form and 'Password' in request.form:
        # Create variables for easy access
        
        Email = request.form['Email']
        Password = request.form['Password']
        
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s AND password = %s', (Email,Password,))

        # Fetch one record and return the result
        account = cursor.fetchone()

         # If account exists in accounts table in out database (Session part)
        if account and check_password(Password, account['password']): 
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['Email']  = account['Email']
            # Redirect to home page
            return redirect(url_for('home'))
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect email/password!'
        
    return render_template('Sign_up.html',msg=msg)

#logout page
@app.route('/logout')
def logout(): 
# Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('Email', None)
# Redirect to login page
   return redirect(url_for('login'))
   
#register page
@app.route('/signup',methods=['GET','POST'])
def register():
    msg=''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'First_Name' in request.form and 'Last_Name' in request.form and 'Number' in request.form and 'Email' in request.form and 'Password' in request.form:
        
        First_Name = request.form['First_Name']
        Last_Name = request.form['Last_Name']
        Number = request.form['Number']
        Email = request.form['Email']
        Password = request.form['Password']

        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE Email = %s', (Email,))
        account = cursor.fetchone()

        # password hashing
        hashed_password = hash_password(Password)

        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', Email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', First_Name):
            msg = 'Username must contain only characters and numbers!'
        elif not First_Name or not Last_Name or not Number or not Password or not Email:
            msg = 'Please fill out the form!'
        else:
            
            # Account doesn't exist, and the form data is valid, so insert the new account into the accounts table
            cursor.execute('INSERT INTO accounts (Firstname,Lastname,Number,Email,Password) VALUES (%s, %s, %s, %s, %s)', (First_Name,Last_Name,Number,Email,hashed_password,))
            mysql.connection.commit()
            msg = 'You have successfully registered!'

    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'

    # Show registration form with message (if any)
    return render_template('Sign_In.html', msg=msg)


#profile page
@app.route('/profile')
def profile():
    if'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not logged in redirect to login page
    return redirect(url_for('register'))


'''
#####
def predict(pickup_datetime,pickup_longitude,pickup_latitude,dropoff_longitude,dropoff_latitude,passenger_count):

  # Load the linear regression model trained earlier
  loaded_model = pickle.load(open('regression_model.sav','rb'))

  # Ensure loaded model's attributes
  #print("Model coefficients:", loaded_model.coef_)  # If coefficients exist

  # Input data for prediction
  input_data = {
      'pickup_datetime':pickup_datetime ,
      'pickup_longitude':pickup_longitude ,
      'pickup_latitude':  pickup_latitude,
      'dropoff_longitude': dropoff_longitude,
      'dropoff_latitude': dropoff_latitude,
      'passenger_count': passenger_count
  }

  # Convert pickup datetime string to datetime object
  input_data['pickup_datetime'] = pd.to_datetime(input_data['pickup_datetime'])

  # Feature engineering
  input_data['year'] = input_data['pickup_datetime'].year
  input_data['month'] = input_data['pickup_datetime'].month
  input_data['day'] = input_data['pickup_datetime'].day
  input_data['hour'] = input_data['pickup_datetime'].hour
  input_data['minute'] = input_data['pickup_datetime'].minute
  input_data['abs_diff_longitude'] = abs(input_data['dropoff_longitude'] - input_data['pickup_longitude'])
  input_data['abs_diff_latitude'] = abs(input_data['dropoff_latitude'] - input_data['pickup_latitude'])
  input_data['distance_km'] = haversine_distance(input_data['pickup_longitude'], input_data['pickup_latitude'],
                                                  input_data['dropoff_longitude'], input_data['dropoff_latitude'])

  # Select relevant features for prediction
  features = ['pickup_longitude', 'pickup_latitude', 'dropoff_longitude', 'dropoff_latitude','passenger_count', 'abs_diff_longitude', 'abs_diff_latitude', 'year', 'month', 'day', 'hour', 'minute', 'distance_km']

  # Arrange input features in the same order as used during model training
  input_features = [input_data[feature] for feature in features]

  # Debugging: Print input feature array
  #print("Input features:", input_features)

  # Make prediction using the loaded model
  prediction = loaded_model.predict([input_features])

  print(prediction)
'''
#to run the program
if __name__ == '__main__':
    app.run(debug = True , port=8000)
    