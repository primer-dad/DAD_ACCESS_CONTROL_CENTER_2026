
from flask import Flask, render_template, request, session, redirect, url_for, make_response, jsonify
import json
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import sys
from authlib.integrations.flask_client import OAuth
from google.cloud import secretmanager
import secrets
from functions import get_employee_by_id, get_home_dashboard_data, get_user_dashboard_data, get_modules, fn_copy_access, validate_user, save_application, save_user_access, get_application_details, save_webapp_user_access, get_user_access_details, get_webapp_user_access_details, get_existing_users, search_hcm_id, enroll_admin, get_admin, get_admin_details, delete_application
# from security_middleware import rasp_check_and_block
from functools import wraps
from rasp_lib.middleware import rasp_check_and_block
# from rasp_lib.patterns import SECURITY_CHECKS

load_dotenv()

oauth_secret_cache = None

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True
)

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# def security_pre_check():
#     print("Security middleware is activated.")
#     block_response = rasp_check_and_block()
#     if block_response:
#         return block_response


@app.before_request
def security_layer():
    result = rasp_check_and_block()
    if result:
        return result


@app.route('/blocked')
def blocked_page():
    return render_template('security_warning.html'), 403


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_details = get_user_details()
        print(f"Active User Role: {user_details['role_type']}")
        if 'user' in session and user_details['role_type'] == 'Super Administrator':
            return f(*args, **kwargs)
        else:
            return jsonify({"error": "Access Denied. Super Admin role required."}), 403

    return decorated_function


# def get_oauth_config_from_secret(project_id: str, secret_id: str) -> dict:
#     secret_client = secretmanager.SecretManagerServiceClient()
#     secret_name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"

#     response = secret_client.access_secret_version(
#         request={"name": secret_name})
#     secret_payload = response.payload.data.decode("UTF-8")

#     oauth_config = json.loads(secret_payload)
#     return oauth_config


# def get_oauth_secret():
#     global oauth_secret_cache
#     try:
#         if oauth_secret_cache:
#             return oauth_secret_cache
#         else:
#             oauth_secret_cache = get_oauth_config_from_secret(
#                 os.getenv('EP_PROJECT_ID'), "access-control-center-google-auth")
#             return oauth_secret_cache
#     except Exception as e:
#         print(f"Error: Error in get_auth_secret")


# oauth_secrets = get_oauth_secret()

# client_id = oauth_secrets["GOOGLE_CLIENT_ID"]
# client_secret = oauth_secrets["GOOGLE_CLIENT_SECRET"]
# redirect_uri = oauth_secrets["GOOGLE_REDIRECT_URI"]

client_id = os.getenv("GOOGLE_CLIENT_ID")
client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=client_id,
    client_secret=client_secret,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    },
    redirect_uri=redirect_uri,
)


@app.route('/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/callback')
def callback():
    token = google.authorize_access_token()
    user_info = google.get(
        'https://openidconnect.googleapis.com/v1/userinfo').json()
    session['user'] = user_info
    return redirect('/')


def clear_cookies(response):
    response.delete_cookie('account_data')
    return response


@app.route('/logout')
def logout():
    response = make_response(redirect('/'))
    clear_cookies(response)
    session.clear()  # optional

    return response

# @app.route("/")
# def index():
#     full_name = "Gilbert Laman"
#     role_type = "Admin"
#     status = "True"
#     user = {
#         "email": "gilbert.laman@priemrgrp.com"
#     }

#     refresh = request.args.get('refresh')
#     if refresh:
#         home_dashboard_data = get_home_dashboard_data(refresh)
#     else:
#         home_dashboard_data = get_home_dashboard_data("")
#     return render_template("index.html", full_name=full_name, role_type=role_type, user=user, status=status, home_dashboard_data=home_dashboard_data)

# def get_user_details():
#     try:
#         admin_details = session.get('admin_details')
#         user = session.get('user')

#         if not isinstance(user, dict):
#             print("Invalid or missing 'user' in session.")
#             user = {}

#         if not isinstance(admin_details, dict):
#             print("Invalid or missing 'admin_details' in session.")
#             admin_details = {}

#         return {
#             "user": user,
#             "full_name": session.get('user', {}).get('name', 'Unknown User'),
#             "picture": session.get('user', {}).get('picture', '/static/default-avatar.png'),
#             "role_type": admin_details.get("role_type", 'guest')
#         }

#     except Exception as e:
#         print(f"Exception in get_user_details: {e}")
#         return {
#             "user": {},
#             "full_name": "Unknown User",
#             "picture": "",
#             "role_type": "guest"
#         }


def get_user_details():
    try:
        user = session.get("user", {})
        admin_details = session.get("admin_details", {})

        if not isinstance(user, dict):
            print("Invalid 'user' in session")
            user = {}

        if not isinstance(admin_details, dict):
            print("Invalid 'admin_details' in session")
            admin_details = {}

        return {
            "user": user,
            "full_name": user.get("name", "Unknown User"),
            "picture": user.get("picture", "/static/default-avatar.png"),
            "role_type": admin_details.get("role_type", "guest")
        }

    except Exception as e:
        print(f"Exception in get_user_details: {e}")
        return {
            "user": {},
            "full_name": "Unknown User",
            "picture": "/static/default-avatar.png",
            "role_type": "guest"
        }


def home(mode):
    user_details = get_user_details()
    # picture=user_details['picture']
    # user=user_details['user']
    # full_name=user_details['full_name']
    # role_type=user_details['role_type']

    if mode:
        home_dashboard_data = get_home_dashboard_data(mode)
    else:
        home_dashboard_data = get_home_dashboard_data("")

    return render_template("index.html",
                           **user_details,
                           status='True',
                           home_dashboard_data=home_dashboard_data)


@app.route('/')
def index():
    print("Checking session for user authentication.")

    refresh = request.args.get('refresh')

    if 'user' in session and session['user']:
        print("User exists in session.")

        if validate_user(session['user']):
            # user_details = get_user_details()
            response = make_response(home(refresh))

            # response.set_cookie('account_data', json.dumps(user_details["user"]))

            return response
        else:
            return render_template('noaccess.html', error="User validation failed.")
    else:
        return render_template('login.html')


@app.route("/refresh_home")
def refresh_home():
    if 'user' in session and session['user']:
        user_details = get_user_details()

        home_dashboard_data = get_home_dashboard_data("refresh")
        return render_template("index.html",
                               **user_details,
                               status="True",
                               home_dashboard_data=home_dashboard_data)
    else:
        return render_template('login.html')


@app.route('/enroll_application')
@admin_required
def enroll_application():

    if 'user' in session and session['user']:
        user_details = get_user_details()
        return render_template("enroll_application.html",
                               **user_details,
                               status="True")
    else:
        return render_template('login.html')


@app.route('/manage_application')
@admin_required
def manage_application():
    if 'user' in session and session['user']:
        user_details = get_user_details()

        app_id = request.args.get('app_id')
        mode = "Manage Application Details"
        app_details_list = get_application_details(app_id)

        print(f"App Details: {app_details_list}")

        app_details = app_details_list[0]

        app_name = app_details.get('app_name', '')
        app_url = app_details.get('app_url', '')
        app_description = app_details.get('app_description', '')
        app_owner = app_details.get('app_owner', '')
        app_status = app_details.get('status', False)

        modules = app_details.get('modules', [])

        print(f"Modules: {modules}")

        return render_template('enroll_application.html',
                               **user_details,
                               status="True",
                               mode=mode,
                               app_id=app_id,
                               app_name=app_name,
                               app_description=app_description,
                               app_owner=app_owner,
                               app_url=app_url,
                               app_status=app_status, module=modules)
    else:
        return render_template('login.html')


@app.route('/enroll_user_home')
def enroll_user_home():
    if 'user' in session and session['user']:
        # full_name = "Gilbert Laman"
        # role_type = "Admin"
        # status = "True"
        # user = {
        #     "email": "gilbert.laman@priemrgrp.com"
        # }

        user_details = get_user_details()
        status = 'True'

        app_id = request.args.get('app_id')
        app_name = request.args.get('app_name')
        app_url = request.args.get('app_url')

        user_dashboard_data = get_user_dashboard_data(app_id)
        if user_dashboard_data is None:
            print("Error: No user data found for the given app_id.")

        return render_template("enroll_user_home.html",
                               **user_details,
                               status=status,
                               app_id=app_id,
                               app_name=app_name,
                               user_dashboard_data=user_dashboard_data,
                               app_url=app_url)
    else:
        return render_template('login.html')


@app.route('/enroll_user_form')
def enroll_user_form():
    if 'user' in session and session['user']:
        user_details = get_user_details()

        app_id = request.args.get('app_id')
        app_name = request.args.get('app_name')
        app_url = request.args.get('app_url')
        modules = get_modules(app_id)

        goto_page = None

        if "https://drive.google.com/" in app_url:
            # ? go to enrollmenr form for google sheets app
            print("Type of app: Google sheet app")
            goto_page = "enroll_new_user_form.html"
        elif "https://lookerstudio.google.com/" in app_url:
            # ? go to enrollment form for looker studio
            print("Type of app: Looker studio app")
            goto_page = ""
        else:
            # ? go to enrollment form for web applications
            print("Type of app: Web app")
            goto_page = "enroll_new_user_form_web_app.html"

            # TODO:
            # TODO GET THE USER ACCOUNT OTHER INFO HERE
            # TODO BETER TO CREATE A FUNCTION THAT WILL HANDLE THE RETRIEVAL OF THE USE ACCOUNT INFO
            # ? Need to retrieve the email, fullname, ticket number, account_status, effectivity date

        return render_template(goto_page,
                               **user_details,
                               status="True",
                               employees="",
                               app_id=app_id,
                               app_name=app_name,
                               app_url=app_url,
                               modules=modules)
    else:
        return render_template('login.html')


@app.route('/manage_user_access_form')
def manage_user_access_form():
    if 'user' in session and session['user']:
        user_details = get_user_details()

        app_id = request.args.get('app_id')
        app_name = request.args.get('app_name')
        app_url = request.args.get('app_url')
        # modules = get_modules(app_id)
        user_email = request.args.get('user_email')

        access_details = None
        print(f"Access Details: {access_details}")

        goto_page = None

        if "https://drive.google.com/" in app_url:
            # ? go to enrollmenr form for google sheets app
            print("Type of app: Google sheet app")
            access_details = get_user_access_details(app_id, user_email)
            goto_page = "manage_user_access_form.html"
        elif "https://lookerstudio.google.com/" in app_url:
            # ? go to enrollment form for looker studio
            print("Type of app: Looker studio app")
            goto_page = ""
        else:
            # ? go to enrollment form for web applications
            print("Type of app: Web app")
            access_details = get_webapp_user_access_details(app_id, user_email)
            goto_page = "manage_user_access_webapp_form.html"

        return render_template(goto_page,
                               **user_details,
                               status="True",
                               employees="",
                               app_id=app_id,
                               app_name=app_name,
                               app_url=app_url,
                               user_email=user_email,
                               access_details=access_details)
    else:
        return render_template('login.html')


@app.route('/search_employee_id')
def search_employee_id():
    ticket_num = request.args.get('ticket_num')
    employee_id = request.args.get('employee_id')
    app_id = request.args.get('app_id')
    app_name = request.args.get('app_name')
    app_url = request.args.get('app_url')
    emp_full_name = ""
    emp_email = ""
    employee_not_found = False
    user_exist = False
    existing_emails = None

    get_user_dashboard_data(app_id)

    if employee_id:
        employee_master_data = get_employee_by_id(employee_id)
    else:
        employee_master_data = None
        print("No employee_id provided.")

    if not employee_master_data:
        employee_not_found = True
    elif "message" in employee_master_data and employee_master_data["message"] == "No data found":
        employee_not_found = True
    else:
        employee = employee_master_data[0] if len(
            employee_master_data) > 0 else None
        if employee:
            emp_full_name = employee.get('FullName', '')
            emp_email = employee.get('EmployeeEmail', '')
        else:
            employee_not_found = True

    # existing_users = session.get('user_master')

    # if existing_users:
    #     existing_emails = {u["email"] for u in existing_users}

    # if emp_email in existing_emails:
    #     user_exist = True

    existing_users = session.get('user_master')
    print(f"Existing users: {existing_users}")
    existing_emails = set()

    if existing_users:
        existing_emails = {u["email"] for u in existing_users}

    if emp_email in existing_emails:
        user_exist = True

    user_details = get_user_details()

    modules = get_modules(app_id)

    if "https://drive.google.com/" in app_url:
        print("Type of app: Google sheet app")
        goto_page = "enroll_new_user_form.html"
    elif "https://lookerstudio.google.com/" in app_url:
        print("Type of app: Looker studio app")
        goto_page = ""
    else:
        print("Type of app: Web app")
        goto_page = "enroll_new_user_form_web_app.html"

    return render_template(goto_page,
                           **user_details,
                           status="True",
                           emp_full_name=emp_full_name,
                           emp_email=emp_email,
                           ticket_num=ticket_num,
                           employee_not_found=employee_not_found,
                           app_id=app_id,
                           app_name=app_name,
                           app_url=app_url,
                           modules=modules, user_exist=user_exist)


@app.route('/copy_access')
def copy_access():
    user_details = get_user_details()

    app_id = request.args.get('app_id')
    app_name = request.args.get('app_name')
    user_email = request.args.get('user_email')
    app_url = request.args.get('app_url')

    return render_template("copy_access.html",
                           **user_details,
                           status="True",
                           app_id=app_id,
                           app_name=app_name,
                           user_email=user_email,
                           app_url=app_url)


@app.route('/copy_access_search')
def copy_access_search():
    employee_id = request.args.get('employee_id')
    app_id = request.args.get('app_id')
    app_name = request.args.get('app_name')
    app_url = request.args.get('app_url')
    user_email = request.args.get('user_email')
    emp_full_name = ""
    emp_email = ""
    employee_not_found = False
    user_exist = False

    # Get employee data based on employee_id
    if employee_id:
        employee_master_data = get_employee_by_id(employee_id)
    else:
        employee_master_data = None
        print("No employee_id provided.")

    # Check if the employee data is valid and not empty
    if not employee_master_data:
        employee_not_found = True
    elif "message" in employee_master_data and employee_master_data["message"] == "No data found":
        employee_not_found = True
    else:
        # Assuming employee_master_data is a list of dictionaries
        employee = employee_master_data[0] if len(
            employee_master_data) > 0 else None
        if employee:
            emp_full_name = employee.get('FullName', '')
            emp_email = employee.get('EmployeeEmail', '')
        else:
            employee_not_found = True

    existing_users = session.get('user_master')
    existing_emails = set()

    if existing_users:
        existing_emails = {u["email"] for u in existing_users}

    if emp_email in existing_emails:
        user_exist = True

    user_details = get_user_details()

    # Pass the flag to the template
    modules = get_modules(app_id)

    return render_template("copy_access.html",
                           **user_details,
                           status="True",
                           emp_full_name=emp_full_name,
                           emp_email=emp_email,
                           employee_not_found=employee_not_found,
                           app_id=app_id,
                           app_name=app_name,
                           app_url=app_url,
                           modules=modules,
                           user_email=user_email, user_exist=user_exist)


@app.route('/copy_user_access', methods=['POST'])
def copy_user_access():
    data = request.get_json()
    source_user_email = data.get('source_user_email')
    target_user_email = data.get('target_user_email')
    app_id = data.get('app_id')
    ticket_number = data.get('ticket_number')
    app = data.get('source_app_name')
    created_by = data.get('created_by')
    full_name = data.get('full_name')

    app_type = None

    if "https://drive.google.com/" in app:
        app_type = "gsheet"
    elif "https://lookerstudio.google.com/" in app:
        print("This is for looker report")
    else:
        app_type = "web"

    fn_copy_access(app_id, source_user_email,
                   target_user_email, ticket_number, app_type, created_by, full_name)

    return jsonify({"message": f"Access copied from {source_user_email} to {target_user_email} for application {app_id}."})


@app.route('/submit-app-data', methods=['POST'])
@admin_required
def submit_app_data():
    try:
        data = request.get_json()

        if not data:
            return ({"error": "No data provided."}), 400

        user = session.get('user')
        user_email = user.get('email')

        save_application(
            hidden_app_id=data.get('hidden_app_id'),
            function_mode=data.get('function_mode'),
            application_name=data.get('application_name'),
            app_url=data.get('application_link'),
            app_description=data.get('app_description'),
            status=data.get('app_status'),
            owner=data.get('owner'),
            # permissions=data.get('permissions'),
            modules=data.get('modules'),
            created_by=data.get('created_by')
        )

        return jsonify({"message": "Success"}), 200

    except Exception as e:
        print(f"Error in submit application data {str(e)}")
        return ({"error": "Error in submit application data"}), 500


@app.route('/submit-user-access', methods=['POST'])
def submit_user_access():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No data provided"}), 400
        else:
            print(f"Data: {data}")

        save_user_access(data)

        return jsonify({"message": "Success"}), 200

    except Exception as e:
        print(f"Error in submit_app_data: {e}")
        return jsonify({"error": "Error in submit_app_data"}), 500


@app.route('/submit-webapp-user-access', methods=['POST'])
def submit_webapp_user_access():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No data provided"}), 400
        else:
            print(f"Data: {data}")

        save_webapp_user_access(data)

        return jsonify({"message": "Success"}), 200

    except Exception as e:
        print(f"Error in submit_app_data: {e}")
        return jsonify({"error": "Error in submit_app_data"}), 500


@app.route('/enroll_administrators')
@admin_required
def enroll_administrators():
    user_details = get_user_details()
    status = "True"

    return render_template('enroll_administrators.html',
                           **user_details,
                           status=status)


@app.route('/search_hcm_id')
def search_hcm_id():
    emp_full_name = ""
    emp_email = ""
    emp_costcode = ""
    emp_position = ""
    employee_not_found = False
    employee_master_data = None
    user_exist = False

    print(f"Searching employee record...")

    hcm_id = request.args.get('employee_id')
    ticket_num = request.args.get('ticket_num')
    # employee_master_data = get_employee_by_id(hcm_id)

    print(employee_master_data)

    user_details = get_user_details()

    # if employee_master_data:
    #     employee = employee_master_data[0] if len(employee_master_data) > 0 else None
    #     if employee:
    #         emp_full_name = employee.get('FullName', '')
    #         emp_email = employee.get('EmployeeEmail', '')
    #         emp_costcode = employee.get('CostCode', '')
    #         emp_position = employee.get('Position', '')
    #     else:
    #         employee_not_found = True
    # else:
    #     employee_master_data = None
    #     employee_not_found = True

    if hcm_id:
        employee_master_data = get_employee_by_id(hcm_id)
    else:
        employee_master_data = None
        print("No employee_id provided.")

    if not employee_master_data:
        employee_not_found = True
    elif "message" in employee_master_data and employee_master_data["message"] == "No data found":
        employee_not_found = True
    else:
        employee = employee_master_data[0] if len(
            employee_master_data) > 0 else None
        if employee:
            emp_full_name = employee.get('FullName', '')
            emp_email = employee.get('EmployeeEmail', '')
            emp_costcode = employee.get('CostCode', '')
            emp_position = employee.get('Position', '')
        else:
            employee_not_found = True

    existing_users = session.get('user_master')
    print(f"User Master: {existing_users}")
    existing_emails = set()

    if existing_users:
        existing_emails = {u["email"] for u in existing_users}

    if emp_email in existing_emails:
        print(f"User: {emp_email} already exists.")
        user_exist = True

    active_step = request.args.get('active_step', 'step2-tab')

    return render_template('enroll_administrators.html', **user_details, employee_id=hcm_id, emp_full_name=emp_full_name, emp_email=emp_email, emp_costcode=emp_costcode, emp_position=emp_position, active_step=active_step, employee_not_found=employee_not_found, ticket_num=ticket_num, user_exist=user_exist)


@app.route('/administrator_home')
def administrator_home():
    user_details = get_user_details()
    status = "True"
    admin_master = get_admin()

    print(f"Admin Master: {admin_master}")

    return render_template('administrator_home.html', **user_details, status=status, administrators=admin_master)


@app.route('/insert_enroll_administrator', methods=['POST'])
@admin_required
def insert_enroll_administrator():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data found."}), 400

        print(f"Data to save: {data}")

        result = enroll_admin(data)

        if result.status_code == 200:
            return jsonify({"status": "success", "message": "User account was created successfully."})
        else:
            return jsonify({"status": "error", "message": "Failed to create user account."}), 500

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"status": "error", "message": f"An unexpected error occurred: {str(e)}"}), 500


@app.route('/manage_admin_details')
def manage_admin_details():
    try:
        admin_id = request.args.get('admin_id')
        user_details = get_user_details()

        if not admin_id:
            return jsonify({"status": "error", "message": "No data found."}), 400

        result = get_admin_details(admin_id)

        print(f"Admin details result: {result}")

        return render_template('manage_administrator_access.html', **user_details, result=result)

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"status": "error", "message": f"An unexpected error occurred: {str(e)}"}), 500


@app.route('/delete_app', methods=['POST'])
@admin_required
def delete_app():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No parameter provided"}), 400

        app_id = data.get('app_id')
        reason = data.get('reason')
        deleted_by = data.get('deleted_by')
        print(f"Rason: {reason}")
        print(f"Selected App ID: {app_id}")

        result = delete_application(app_id, reason, deleted_by)

        if not result or result.get("status") != "success":
            return jsonify({"error": "Failed to delete application"}), 500

        return jsonify({"message": "Deletion Success"}), 200

    except Exception as e:
        print(f"Error in application deletion: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/activity_logs')
def activity_logs():
    user_details = get_user_details()

    return render_template('activity_logs.html', **user_details)


@app.route('/observability')
def observability():
    user_details = get_user_details()

    return render_template('observability.html', **user_details)


if __name__ == "__main__":
    app.run(debug=True)
