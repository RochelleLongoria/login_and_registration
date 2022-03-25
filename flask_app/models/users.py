from flask_app.config.mysqlconnection import connectToMySQL
from flask_app import app
from flask import flash
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

class Users:
    db = 'users_assignment'

    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.password_confirmation = data['password_confirmation']



    # ------classmethod---------->
    @classmethod
    def save_login(cls,data):
        query = """
                INSERT INTO users (email, password, password_confirmation)
                            values (%(email)s, %(password)s, %(password_confirmation)s);
                """
        mysql = connectToMySQL('users_assignment').query_db(query,data)
        return mysql

    @classmethod
    def save_registration(cls,data):
        query = """
                INSERT INTO users (first_name, last_name, email, password, password_confirmation)
                            values (%(first_name)s, %(last_name)s, %(email)s, %(password)s, %(password_confirmation)s);
                """
        mysql = connectToMySQL('users_assignment').query_db(query,data)
        return mysql

    @classmethod
    def get_by_email(cls,data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL(cls.db).query_db(query,data)
        # Didn't find a matching user   
        if len(result) < 1:
            return False
        return cls(result[0])

    @classmethod
    def user_info(cls,data):
        query = "SELECT * from users Where id = %(id)s;"
        mysql = connectToMySQL('users_assignment').query_db(query,data)
        return mysql



#------ staticmethod--------->

    @staticmethod
    def validate_register(user):
        is_valid = True
        if len(user['first_name']) < 3:
                flash("first_name must be at least 3 characters.")
                is_valid = False
        if len(user['last_name']) < 3:
            flash("last_name must be at least 3 characters.")
            is_valid = False
        if len(user['email']) < 5:
            flash("Are you sure you aren't trolling?.")
            is_valid = False
        if len(user['password']) < 3:
            flash("cool beans.")
            is_valid = False
        return is_valid


    @staticmethod
    def validate_login(form_data):
        is_valid = True
        user_from_db = Users.get_by_email(form_data)
        if not user_from_db:
            flash("Invalid Email/Password")
            is_valid = False

        elif not bcrypt.generate_password_hash(user_from_db.password, form_data['password']):
            #if we get False after checking the password
            flash("Invalid Email/Password")
            is_valid = False

        return is_valid