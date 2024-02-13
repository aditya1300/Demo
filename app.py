from google.cloud import bigquery
import pandas_gbq
import flask
from flask import render_template, jsonify, request, redirect, url_for, session
import pandas as pd
from markupsafe import Markup

import numpy as np
from io import BytesIO

from googleapiclient.errors import HttpError
from google.oauth2 import id_token
# from google.auth.transport import requests
from google.oauth2 import service_account
import google.auth

from google.cloud import storage
from google.cloud import pubsub_v1

# import google.auth.transport.requests
import googleapiclient.discovery
import os
import json
import requests
import urllib.parse
import base64
import gitlab
from base64 import b64encode
import time

# OTP and password encrpytion
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import bcrypt

from datetime import datetime, timedelta

# Define a dictionary to store failed login attempts and last attempt time
failed_login_attempts = {}

MAX_FAILED_ATTEMPTS = 3

TOTAL_FAILED_ATTEMPTS = 0


app = flask.Flask(__name__)
""" LOGIN ROUTES """
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY", "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"
)  # Change this to a random secret key

GOOGLE_CLIENT_ID = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"  # Replace this with your actual Google Client ID

# GIT_PROJECT_ID = '48002477'
GIT_PROJECT_ID = "51301524"
# GCP_PROJECT_ID = "fine-eye-a"
GCP_PROJECT_ID = "compliance-reporting-platform"

# Set your Google Cloud project ID and bucket name
# project_id = 'fine-eye-a'
bucket_name = "easyinsurance-data1"
folder_name = "Raw_Data/"  # Optional: specify the folder within the bucket

# Initialize the Pub/Sub client
pubsub_client = pubsub_v1.PublisherClient()
topic_name1 = "StepI-DI"  # Replace with your Pub/Sub topic name

# Set up the MIMEText and MIMEMultipart objects
msg = MIMEMultipart()
# msg["From"] = "prasad.b@predoole.com"
# msg["Subject"] = "OTP verification"  # Add your subject here

sender_mail = "prasad.b@predoole.com"
sender_password = "Arnav@9492."
# mail_platform = "outlook.office365.com"
mail_platform = "smtp-mail.outlook.com"


# A dictionary to store user credentials (for demonstration purposes only)
def fetch_user_credentials():
    # Create a BigQuery client
    client = bigquery.Client()

    # Replace 'your_dataset' and 'your_table' with your actual dataset and table names
    query = f"""
        SELECT email, password, role, template, approval, verification FROM `{GCP_PROJECT_ID}.user_Oauth.Authentication`
    """

    # print(client)

    # Run the query to fetch user credentials from BigQuery
    query_job = client.query(query)
    # print('>>', query_job.result())

    rows = query_job.result()

    # print(json.dumps(rows))
    # print(list(rows))

    # Convert the rows to a dictionary with email as the key and password as the value
    # user_credentials = {row["email"]: row["password"] for row in rows}
    # print('user_credentials',user_credentials)

    # Convert the rows to a list of dictionaries
    user_credentials_list = [
        {
            "email": row["email"],
            "password": row["password"].decode("utf-8")
            if isinstance(row["password"], bytes)
            else row["password"],
            "role": row["role"],
            "template": row["template"],
            "approval": row["approval"],
            "verification": row["verification"],
        }
        for row in rows
    ]

    # Convert the list of dictionaries to a JSON-formatted string
    user_credentials_json = json.dumps(user_credentials_list, indent=2)

    # print('user_credentials_json>> ',user_credentials_json)

    return user_credentials_json


# Function to verify Google ID token
def verify_google_id_token(id_token_str):
    try:
        # Verify the Google ID token
        idinfo = id_token.verify_oauth2_token(
            id_token_str, requests.Request(), GOOGLE_CLIENT_ID
        )
        # print('idinfo',idinfo)
        return idinfo
    except ValueError:
        return None


def check_user_role(userdata):
    # print(userdata)
    if userdata["role"] == "Admin":
        return True
    elif userdata["role"] == None:
        return "Not Assign"
    else:
        if userdata["verification"] == "Yes":
            if userdata["approval"] == "Yes":
                return True
            else:
                return "Unapproved"
        else:
            return "Unverified"


def verify_email_and_password(email, password):
    session.clear()
    # Fetch user credentials from BigQuery
    user_credentials = fetch_user_credentials()

    # print("user_credentials:", type(user_credentials))

    user_credentials = json.loads(user_credentials)

    # Check if the email exists in the user credentials fetched from BigQuery
    for user in user_credentials:
        if user["email"] == email:
            # print(user["email"])

            check_user = check_user_role(user)

            if check_user == True:
                # If the email exists, check if the provided password matches the stored hashed password
                stored_hashed_password = user["password"]
                # print(stored_hashed_password)

                # Check if the provided password matches the stored hashed password
                if bcrypt.checkpw(
                    password.encode("utf-8"), stored_hashed_password.encode("utf-8")
                ):
                    # Passwords match
                    # Check if the email is present in the IAM principal using the IAM API
                    roles = fetch_iam_roles()
                    # print(roles)
                    if roles is not None:
                        session["email"] = email
                        session["roles"] = roles
                        session["role"] = user["role"]
                        session["template"] = user["template"]
                        session["approval"] = user["approval"]
                        session["verification"] = user["verification"]
                        return True
                    else:
                        return False  # Email not found in IAM principal
            else:
                return check_user
    return False  # Email and/or password invalid


def is_email_in_iam(email):
    # Use google.auth to get the credentials
    credentials, project_id = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )

    # Fetch IAM policies for the project
    service = googleapiclient.discovery.build(
        "cloudresourcemanager", "v1", credentials=credentials
    )
    policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()

    # Extract members (users and service accounts) from IAM policies
    members = [
        member
        for binding in policy.get("bindings", [])
        for member in binding.get("members", [])
    ]

    # print(members)
    # print(f"user:{email}" in members)

    # Check if the email exists in the members list
    return f"user:{email}" in members


def fetch_iam_roles():
    # Use google.auth to get the credentials
    credentials, project_id = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )

    # Fetch IAM roles for the project
    service = googleapiclient.discovery.build("iam", "v1", credentials=credentials)
    roles_response = (
        service.projects().roles().list(parent=f"projects/{project_id}").execute()
    )
    roles = [role["name"] for role in roles_response.get("roles", [])]

    return roles


def gettableID():
    # Request body can be accessed as request.json
    # print(request.json)
    # project_id = 'fine-eye-a'
    client = bigquery.Client(project=GCP_PROJECT_ID)

    datasets = client.list_datasets()
    aldatasets = [dataset.dataset_id for dataset in datasets]

    temp = []
    for i in aldatasets:
        dataset_ref = client.dataset(i)
        tables = client.list_tables(dataset_ref)
        for table in tables:
            # print(table.table_id)
            temp.append(f".{i}.{table.table_id}")

    # print("temp>>", temp)
    return temp


dataset = gettableID()

""" def getReports():
    # GitLab API endpoint
    gitlab_url = "https://gitlab.com/api/v4"
    # project_id = "48002477"
    file_path = "Reports"
    branch_name = "original-reports"
    # access_token = "glpat-s_aKYFKWsLkQcJNWwugE"

    # Path to the folder you want to search for Excel files
    folder_path = "Reports"

    # Construct the API URL
    api_url = f"{gitlab_url}/projects/{GIT_PROJECT_ID}/repository/tree?path={folder_path}&ref={branch_name}"

    # Set up the request headers
    # headers = {
    #     "PRIVATE-TOKEN": access_token,
    # }

    # Send the GET request to retrieve the file content
    response = requests.get(api_url)
    # response = requests.get(api_url, headers=headers)

    # Check if the request was successful (HTTP status code 200)
    if response.status_code == 200:
        file_list = response.json()
        # print('file_list: ',file_list)

        # Filter the list to get only Excel files (assuming file extension is ".xlsx")
        # excel_files = [file for file in file_list if file["type"] == "blob" and file["name"].endswith(".xlsx")]
        excel_files = [
            file for file in file_list if file.get("name").lower().endswith(".xlsx")
        ]
        # print('excel_files: ', excel_files)

        fileArr = []

        # Print details of each Excel file
        for file in excel_files:
            # Encode the file path
            encoded_file_path = urllib.parse.quote(file["path"], safe="")

            api_url = f"{gitlab_url}/projects/{GIT_PROJECT_ID}/repository/files/{encoded_file_path}/raw?ref={branch_name}"
            # print(api_url)

            # print(file['name'].split('.')[0])
            
            fileArr.append(
                {
                    "filename": file["name"],
                    "templatename": file["name"].split(".xlsx")[0],
                    "fileurl": api_url,
                }
            )

        return fileArr

    else:
        print(f"Failed to retrieve file. Status code: {response.status_code}")
        # print(response.text)
 """


def getReports():
    # GitLab API endpoint
    gitlab_url = "https://gitlab.com/api/v4"
    # project_id = "48002477"  # Replace with your project ID
    file_path = "Reports"
    branch_name = "original-reports"
    access_token = "glpat-s_aKYFKWsLkQcJNWwugE"  # Replace with your access token

    # Path to the folder you want to search for Excel files
    folder_path = "Reports"

    # Create an empty list to store all files
    all_files = []

    # Initial page number
    page = 1

    while True:
        # Construct the API URL with pagination
        api_url = f"{gitlab_url}/projects/{GIT_PROJECT_ID}/repository/tree?path={folder_path}&ref={branch_name}&page={page}&per_page=100"

        # Set up the request headers with your access token
        headers = {
            "PRIVATE-TOKEN": access_token,
        }

        # Send the GET request to retrieve the file content
        # response = requests.get(api_url, headers=headers)
        response = requests.get(api_url)

        # Check if the request was successful (HTTP status code 200)
        if response.status_code == 200:
            file_list = response.json()

            # Filter the list to get only Excel files (assuming file extension is ".xlsx")
            excel_files = [
                file for file in file_list if file.get("name").lower().endswith(".xlsx")
            ]

            # If there are no more files, break the loop
            if not excel_files:
                break

            for file in excel_files:
                # Encode the file path
                encoded_file_path = urllib.parse.quote(file["path"], safe="")

                api_url = f"{gitlab_url}/projects/{GIT_PROJECT_ID}/repository/files/{encoded_file_path}/raw?ref={branch_name}"

                all_files.append(
                    {
                        "filename": file["name"],
                        "templatename": file["name"].split(".xlsx")[0],
                        "fileurl": api_url,
                    }
                )

            # Increment the page number for the next request
            page += 1

        else:
            print(f"Failed to retrieve file. Status code: {response.status_code}")
            # Handle the error, or you can add error handling logic here

    # print('all_files: ',all_files)

    return all_files


@app.route("/", methods=["GET"])
def home():
    session.clear()
    return render_template("./Layout/login.html", message="Empty Inputs")


""" Login Routes """


@app.route("/", methods=["POST"])
def login():
    session.clear()
    row_data = flask.request.json
    email = row_data["email"]
    password = row_data["password"]

    message = ""

    # Check if there's a failed attempts counter in the session
    global TOTAL_FAILED_ATTEMPTS

    passw = verify_email_and_password(email, password)

    if passw == True:
        return {"condition": "true"}
    elif passw == "Not Assign":
        return {
            "condition": "false",
            "message": "Entered email is under review. Please contact your administrator.",
        }
    elif passw == "Unapproved":
        return {
            "condition": "false",
            "message": "Entered email is not an approved user. Please contact your administrator.",
        }
    elif passw == "Unverified":
        return {
            "condition": "false",
            "message": "Entered email is not a verified user. Please reset your password.",
        }
    else:
        # Increment the failed attempts counter
        TOTAL_FAILED_ATTEMPTS = TOTAL_FAILED_ATTEMPTS + 1

        if TOTAL_FAILED_ATTEMPTS >= MAX_FAILED_ATTEMPTS:
            send_email(
                email,
                "Account Locked",
                "Your account has been locked due to multiple failed login attempts.",
            )
            message = "Your account has been locked for 1 hour since you entered an invalid password multiple times."
            return {"condition": "false", "message": message}
        else:
            message = "Invalid credentials"
            return {"condition": "false", "message": message}


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


""" Forgot Routes """


@app.route("/forgotpassword")
def forgotpassword():
    # session.clear()
    return render_template("/Layout/forgotpassword.html")


@app.route("/verifyemail", methods=["POST"])
def verifyemail():
    # session.clear()
    row_data = flask.request.json
    # print(row_data)

    email = row_data["email"]
    # print(email)
    # password = row_data["oldpassword"]

    # Set up BigQuery client
    client = bigquery.Client()

    # Define the BigQuery SQL query to get the count
    query = f"""
        SELECT email, password, template
        FROM `{GCP_PROJECT_ID}.user_Oauth.Authentication` Where email = '{email}'
    """

    # print(query)

    query_job = client.query(query)

    # Execute the query and get the count
    rows = query_job.result()

    user_credentials = {row["email"] for row in rows}
    # print(user_credentials)

    # print(len(user_credentials))

    if len(user_credentials) == 1:
        otp = generate_otp()
        subject = "OTP Verfication"
        body = f"The OTP for verification of user is {otp}"
        send_email(email, subject, body)
        # print(otp, email)
        update_query = f"""UPDATE `{GCP_PROJECT_ID}.user_Oauth.Authentication` SET OTP = {otp} WHERE email='{email}'"""
        # print(update_query)
        client.query(update_query)
        client.close()

        return {"condition": "true"}
    else:
        return {"condition": "false"}
    # return render_template("/Layout/forgotpassword.html")


""" Register Routes """


@app.route("/register")
def register():
    # session.clear()
    return render_template("/Layout/register.html")


@app.route("/registeruser", methods=["POST"])
def otp_mail_sender():
    row_data = flask.request.json
    # print(row_data)

    email = row_data["email"]
    fullname = row_data["fullname"]

    # Set up BigQuery client
    client = bigquery.Client()

    # Define the BigQuery SQL query to get the count
    query = f"""
        SELECT email, password, template
        FROM `{GCP_PROJECT_ID}.user_Oauth.Authentication` Where email = '{email}'
    """

    # print(query)

    query_job = client.query(query)

    # Execute the query and get the count
    # rows = np.array(query_job.result()).size
    rows = list(query_job.result())

    count = len(rows)

    # print(count)

    if count == 0:
        otp = generate_otp()
        subject = "OTP Verfication"
        body = f"The OTP for verification of user is {otp}"
        send_email(email, subject, body)
        new_user = new_user_insert(email, otp)
        
    else:
        return {"condition": "false", "message": "User Already Exists"}

    return {"condition": "true"}


""" Generate OTP and Email """


def generate_otp():
    otp = random.randrange(100000, 1000000)

    # print(email, subject, body)
    return otp


def send_email(email, subject, body):
    # Set up the MIMEText and MIMEMultipart objects
    msg = MIMEMultipart()
    msg["From"] = sender_mail
    msg["To"] = email
    # msg['To'] = receiver
    msg["Subject"] = subject  # Add your subject here

    # The actual message
    body = f"{body}"
    msg.attach(MIMEText(body, "plain"))

    """ # Establish a connection to the SMTP server
    server = smtplib.SMTP_SSL(mail_platform, 465)

    # Enable debugging to get more information
    server.set_debuglevel(1)

    try:
        # Start TLS for security
        server.starttls()

        # Login to your Outlook Office 365 account
        server.login(sender_mail, sender_password)

        # Send the email
        server.sendmail(sender_mail, email, msg.as_string())

        print("Email sent successfully!")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Quit the server
        server.quit() """
    smtp = smtplib.SMTP(mail_platform, port=587)
    smtp.starttls()
    smtp.login(sender_mail, sender_password)
    smtp.sendmail(sender_mail, email, msg.as_string())
    smtp.quit()


def new_user_insert(receiver: str, otp: int):
    # Create a BigQuery client
    client = bigquery.Client()
    # print(otp, len(otp))
    table_id = f"{GCP_PROJECT_ID}.user_Oauth.Authentication"
    query = f"INSERT INTO `{table_id}`(email,OTP) VALUES ('{receiver}',{otp})"

    # Insert the data into the table
    result = client.query(query)
    client.close()
    
    return result


@app.route("/verifyotp", methods=["POST"])
def verifyotp():
    row_data = flask.request.json

    email = row_data["email"]
    otp = row_data["otp"]

    # print(otp, len(otp))

    if len(otp) == 6:
        # Set up BigQuery client
        client = bigquery.Client()

        # Define the BigQuery SQL query to get the count
        query = f"""
            SELECT * FROM `{GCP_PROJECT_ID}.user_Oauth.Authentication` Where email = '{email}' and OTP = {otp}
        """

        # print(query)

        query_job = client.query(query)

        # Execute the query and get the count
        rows = query_job.result()

        # print(rows)

        # for row in rows:
        #     print(row)

        # count = list(result)[0]['count']

        user_credentials = {row["email"]: row["OTP"] for row in rows}

        # print(user_credentials)

        if len(user_credentials) == 1:
            return {"condition": "true"}
        else:
            return {"condition": "false", "message": "Invalid OTP. Please Check"}
    else:
        return {"condition": "false", "message": "OTP must be 6 digit."}


@app.route("/insertuserpassword", methods=["POST"])
def set_password():
    row_data = flask.request.json

    email = row_data["email"]
    typee = row_data["type"]
    fullname = row_data["fullname"]
    # password = row_data["password"]

    password = bytes(row_data["password"], encoding="utf-8")
    # password = bytes(password, encoding="utf-8")
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    # print(hashed)
    # Create a BigQuery client
    client = bigquery.Client()
    table_id = f"{GCP_PROJECT_ID}.user_Oauth.Authentication"
    if typee == "register":
        query = f"UPDATE `{table_id}` SET password = {hashed}, verification = 'Yes' WHERE email='{email}'"
        message = "User Added Successfully."
        subject = "Compliance Reporting Platform Registration"
        body = f"Hi {fullname}, Thank you for registering your account at our website. Your account need the approval before login. We hope for your kind waiting."
        send_email(email, subject, body)
    elif typee == "forgot":
        query = f"UPDATE `{table_id}` SET password = {hashed}, verification = 'Yes' WHERE email='{email}'"
        message = "Password updated successfully."

    # Insert the data into the table
    job = client.query(query)
    # print(job.state)
    client.close()

    return {"condition": "true", "message": message}


@app.route("/accessdenied")
def access_denied():
    session.clear()
    return render_template("./Layout/error.html")


@app.route("/sessiontimeout")
def sessiontimeout():
    return render_template("./Layout/sessiontimeout.html")


@app.errorhandler(404)
def invalid_route(e):
    return render_template("./Layout/error.html"), 404


@app.errorhandler(400)
def invalid_route(e):
    return render_template("./Layout/sessiontimeout.html"), 504


@app.errorhandler(408)  # Adding a handler for session timeout (HTTP status code 408)
def session_timeout(e):
    return render_template("./Layout/sessiontimeout.html"), 408


""" TABLE ROUTES """


def fetch_data(table_id):
    client = bigquery.Client()
    query = f"SELECT * FROM `{table_id}`"
    data = client.query(query).to_dataframe()
    # print(data)
    return data


def fetch_LOB(table_id):
    client = bigquery.Client()
    query = f"SELECT * FROM `{table_id}`"
    data = client.query(query).to_dataframe()
    return data


""" GENERATE FUNCTIONS """


def generate_lob_table(data, LOB):
    header = data.columns.values
    select_list = pd.Series(LOB["IRDAI_LOB"]).values
    html_table = "<table id='table1' class='table table-bordered table-hover' class='display' cellspacing='0' width='100%' style='height: 300px;'>"
    html_table += "<thead><tr><th>Company LOB</th><th>Product Code</th><th>IRDAI LOB</th></tr></thead>"
    html_table += "<tbody>"

    for index, row in data.iterrows():
        Irdai_lobif = row["IRDAI_LOB"]
        if row["IRDAI_LOB"] not in select_list:
            Irdai_lobif = "Please Select"
        else:
            Irdai_lobif = row["IRDAI_LOB"]
        html_table += "<tr>"
        html_table += f"<td>{row['Company_LOB']}</td>"
        html_table += f"<td>{row['Product_Code']}</td>"
        # html_table += f"<td contenteditable='true' Product_Code={row['Product_Code']} IRDAI_LOB='{row['IRDAI_LOB']}' name='IRDAI_LOB' >{row['IRDAI_LOB']}</td>"
        html_table += f"<td name='IRDAI_LOB' >"
        html_table += f"<select class='select_lob' Product_Code='{row['Product_Code']}' IRDAI_LOB='{Irdai_lobif}' id='lob_list'>"
        html_table += f"<option>Please Select</option>"
        for indx, elem in enumerate(select_list):
            if elem == Irdai_lobif:
                html_table += f"<option value='{elem}' selected>{elem}</option>"
            else:
                html_table += f"<option value='{elem}'>{elem}</option>"
        html_table += "</select>"
        html_table += "</td>"
        html_table += "</tr>"
    html_table += "</tbody>"
    html_table += "</table>"

    return Markup(html_table)


def generate_lob_all_table(data, LOB, category):
    # print(category)
    header = data.columns.values
    lobcolmtype = "IIB_LOB" if category == "IIB" else "IRDAI_LOB"
    select_list = pd.Series(LOB[lobcolmtype]).values
    lobtype = "IIB LOB" if category == "IIB" else "IRDAI LOB"
    html_table = "<table id='table1' class='table table-bordered table-hover' class='display' cellspacing='0' width='100%' style='height: 300px;'>"
    html_table += f"<thead><tr><th>Company LOB</th><th>Product Code</th><th>{lobtype}</th></tr></thead>"
    html_table += "<tbody>"

    for index, row in data.iterrows():
        Irdai_lobif = row[lobcolmtype]
        if row[lobcolmtype] not in select_list:
            Irdai_lobif = "Please Select"
        else:
            Irdai_lobif = row[lobcolmtype]
        html_table += "<tr>"
        html_table += f"<td>{row['Company_LOB']}</td>"
        html_table += f"<td>{row['Product_Code']}</td>"
        # html_table += f"<td contenteditable='true' Product_Code={row['Product_Code']} IRDAI_LOB='{row['IRDAI_LOB']}' name='IRDAI_LOB' >{row['IRDAI_LOB']}</td>"
        html_table += f"<td name='IRDAI_LOB'>"
        html_table += f"<select class='select_lob' Product_Code='{row['Product_Code']}' {lobcolmtype}='{Irdai_lobif}' id='lob_list'>"
        html_table += f"<option>Please Select</option>"
        for indx, elem in enumerate(select_list):
            if elem == Irdai_lobif:
                html_table += f"<option value='{elem}' selected>{elem}</option>"
            else:
                html_table += f"<option value='{elem}'>{elem}</option>"
        html_table += "</select>"
        html_table += "</td>"
        html_table += "</tr>"
    html_table += "</tbody>"
    html_table += "</table>"

    return Markup(html_table)


def generate_channel_table(data, LOB):
    header = data.columns.values
    select_list = pd.Series(LOB["IRDAI_Channel"]).values
    # select_list = pd.Series(LOB['IRDAI_Channel']).values
    channel_table = "<table id='table1' class='table table-bordered table-hover' class='display' cellspacing='0' width='100%' style='height: 300px;'>"
    channel_table += (
        "<thead><tr><th>Company Channel</th><th>IRDAI Channel</th></tr></thead>"
    )
    channel_table += "<tbody>"
    for index, row in data.iterrows():
        Irdai_channel = row["IRDAI_Channel"]
        if row["IRDAI_Channel"] not in select_list:
            Irdai_channel = "Please Select"
        else:
            Irdai_channel = row["IRDAI_Channel"]
        channel_table += "<tr>"
        # channel_table += f"<td>{row['Main Channel']}</td>"
        channel_table += f"<td>{row['Company_Channel']}</td>"
        channel_table += f"<td name='IRDAI_Channel'>"
        channel_table += f"<select class='select_lob' Company_Channel='{row['Company_Channel']}' IRDAI_Channel='{Irdai_channel}' id='lob_list'>"
        channel_table += f"<option>Please Select</option>"
        for indx, elem in enumerate(select_list):
            if elem == Irdai_channel:
                channel_table += f"<option value='{elem}' selected>{elem}</option>"
            else:
                channel_table += f"<option value='{elem}'>{elem}</option>"
        channel_table += "</select>"
        channel_table += "</td>"
        channel_table += "</tr>"
    channel_table += "</tbody>"
    channel_table += "</table>"
    return Markup(channel_table)


def generate_channel_all_table(data, LOB):
    header = data.columns.values
    select_list = pd.Series(LOB["IRDAI_Channel"]).values
    # print('select_list',select_list,':::',LOB['IRDAI_Channel'])
    # select_list = pd.Series(LOB['IRDAI_Channel']).values
    channel_table = "<table id='table1' class='table table-bordered table-hover' class='display' cellspacing='0' width='100%' style='height: 300px;'>"
    channel_table += (
        "<thead><tr><th>Company Channel</th><th>IRDAI Channel</th></tr></thead>"
    )
    channel_table += "<tbody>"
    for index, row in data.iterrows():
        Irdai_channel = row["IRDAI_Channel"]
        if row["IRDAI_Channel"] not in select_list:
            Irdai_channel = "Please Select"
        else:
            Irdai_channel = row["IRDAI_Channel"]
        channel_table += "<tr>"
        channel_table += f"<td>{row['Company_Channel']}</td>"
        channel_table += f"<td name='IRDAI_Channel'>"
        channel_table += f"<select class='select_lob' Company_Channel='{row['Company_Channel']}' IRDAI_Channel='{Irdai_channel}' id='lob_list'>"
        channel_table += f"<option>Please Select</option>"
        for indx, elem in enumerate(select_list):
            if elem == Irdai_channel:
                channel_table += f"<option value='{elem}' selected>{elem}</option>"
            else:
                channel_table += f"<option value='{elem}'>{elem}</option>"
        channel_table += "</select>"
        channel_table += "</td>"
        channel_table += "</tr>"
    channel_table += "</tbody>"
    channel_table += "</table>"
    return Markup(channel_table)


""" MASTER FUNCTIONS """


def update_data(table_id, row_data, irdaiType):
    # print(irdaiType)
    try:
        if irdaiType == "IRDAI_LOB":
            for row in row_data:
                update_query = f"""
                    UPDATE `{table_id}`
                    SET IRDAI_LOB = '{row["IRDAI_LOB_value"]}'
                    WHERE Product_Code = '{row["prod_code_value"]}'
                """
                pandas_gbq.read_gbq(update_query, dialect="standard")
        elif irdaiType == "IIB_LOB":
            for row in row_data:
                # print(row_data)
                update_query = f"""
                    UPDATE `{table_id}`
                    SET IIB_LOB = '{row["IIB_LOB_value"]}'
                    WHERE Product_Code = '{row["prod_code_value"]}'
                """
                pandas_gbq.read_gbq(update_query, dialect="standard")
        elif irdaiType == "IRDAI_Channel":
            for row in row_data:
                update_query = f"""
                    UPDATE `{table_id}`
                    SET IRDAI_Channel = '{row["IRDAI_Channel"]}'
                    WHERE Company_Channel = '{row["Company_Channel_value"]}'
                """
                pandas_gbq.read_gbq(update_query, dialect="standard")
        return "true"
    except Exception as e:
        print(e)
        return "false"


""" DASHBOARD ROUTE """


# Function to upload a file to Google Cloud Storage bucket
def upload_blob(bucket_name, source_file_name, destination_blob_name):
    storage_client = storage.Client(project=GCP_PROJECT_ID)
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    blob.upload_from_filename(source_file_name)

    print(f"File {source_file_name} uploaded to {destination_blob_name}.")


# Function to send a Pub/Sub notification when upload is successful
# Function to send a Pub/Sub notification when upload is successful
def send_pubsub_notification(filename):
    try:
        message = {"filename": filename}

        message_json = json.dumps(message)
        data = message_json.encode("utf-8")  # Encode as bytes

        topic_path = pubsub_client.topic_path(GCP_PROJECT_ID, topic_name1)

        # Publish the message to the Pub/Sub topic
        response = pubsub_client.publish(topic_path, data=data)

        # Check the response for any errors
        if response.exception():
            print(f"Error publishing message: {response.exception()}")
        else:
            print(f"Message published to Pub/Sub topic: {topic_name1}")

    except Exception as e:
        # Handle any exceptions that may occur during message publication
        print(f"Error sending Pub/Sub notification: {str(e)}")


@app.route("/actionpoints")
def index():
    if "email" in session:
        email = session["email"]
        roles = session.get("roles", [])
        role = session["role"]
        template = session["template"]
        approval = session["approval"]
        verification = session["verification"]
        lob_access = ""
        channel_access = ""
        both_access = ""
        # print(role)
        if role != "Admin":
            gettemplatelist = json.loads(getTemplates())
            # print("template>>", gettemplatelist)

            lob_access = "true" if gettemplatelist["LOB_ACCESS"] == 0 else "false"
            channel_access = (
                "true" if gettemplatelist["CHANNEL_ACCESS"] == 0 else "false"
            )
            both_access = "true" if gettemplatelist["BOTH_ACCESS"] == 0 else "false"

        return render_template(
            "index.html",
            email=email.split("@")[0],
            roles=roles,
            role=role,
            template=template,
            approval=approval,
            verification=verification,
            lob_access=lob_access,
            channel_access=channel_access,
            both_access=both_access,
        )
    return redirect(url_for("access_denied"))


# Route to handle file upload
@app.route("/uploadfile", methods=["POST"])
def uploadfile():
    if "file" not in request.files:
        return "No file part"

    file = request.files["file"]

    if file.filename == "":
        return "No selected file"

    local_file_path = os.path.join(
        r"C:/Users/Laptop_User/Downloads/Upload Data", file.filename
    )

    try:
        # Upload the file to Google Cloud Storage
        destination_blob_name = os.path.join(folder_name, file.filename)
        upload_blob(bucket_name, local_file_path, destination_blob_name)

        # Send a Pub/Sub notification with the filename
        send_pubsub_notification(file.filename)

        return "File uploaded successfully"
    except Exception as e:
        return "Upload failed. Error: " + str(e)


# Route to get the count from BigQuery
@app.route("/getcount")
def get_count():
    try:
        # Set up BigQuery client
        client = bigquery.Client()

        # Define the BigQuery SQL query to get the count
        query = f"""
            SELECT COUNT(*) as count
            FROM `{GCP_PROJECT_ID}.Dashboard_Content.LOB_Mapping`
        """

        # print(query)

        query_job = client.query(query)

        # Execute the query and get the count
        result = query_job.result()
        # count = list(result)[0]['count']

        for row in result:
            print(row)

        # Return the count as JSON response
        return {"count": row[0]}

        # print('>>>>',result)

        # Return the count as JSON response
        # return jsonify({'count': count})

    except Exception as e:
        return (
            jsonify({"error": str(e)}),
            500,
        )  # Handle any exceptions and return an error response if needed


@app.route("/getlobcount")
def get_lobcount():
    try:
        # Set up BigQuery client
        client = bigquery.Client()

        # Define the BigQuery SQL query to get the count
        query = f"""
            select COUNT(Lob_Null_Count) from `{GCP_PROJECT_ID}.Dashboard_Content.LOB_Mapping`
        """

        query_job = client.query(query)

        # Execute the query and get the count
        result = query_job.result()

        # print('result: ',list(result))

        # Iterate over the rows
        for row in result:
            print(row)

        # Return the count as JSON response
        return {"count": row[0]}

    except Exception as e:
        print(e)
        return (
            jsonify({"error": str(e)}),
            500,
        )  # Handle any exceptions and return an error response if needed


@app.route("/getruralcount")
def get_ruralcount():
    try:
        # Set up BigQuery client
        client = bigquery.Client()

        # Define the BigQuery SQL query to get the count
        query = f"""
            select COUNT(Ruralflag_Null_Count) from `{GCP_PROJECT_ID}.Dashboard_Content.RuralFlag_Mapping`;
        """

        query_job = client.query(query)

        # Execute the query and get the count
        result = query_job.result()

        # print('result: ',list(result))

        # Iterate over the rows
        for row in result:
            print(row)

        # Return the count as JSON response
        return {"ruralcount": row[0]}

    except Exception as e:
        print(e)
        return (
            jsonify({"error": str(e)}),
            500,
        )  # Handle any exceptions and return an error response if needed


@app.route("/getsocialcount")
def get_socialflagcount():
    try:
        # Set up BigQuery client
        client = bigquery.Client()

        # Define the BigQuery SQL query to get the count
        query = f"""
           SELECT count(*) from `{GCP_PROJECT_ID}.Demo_Easy_Insurance.Premium_Transformed_Data` where Rural_Social_Flag is null;
        """
        """ query = 
           SELECT Policy_No,count(*) from `{GCP_PROJECT_ID}.Demo_Easy_Insurance.Premium_Transformed_Data` where Rural_Social_Flag is null group by Policy_No;
        """

        query_job = client.query(query)

        # Execute the query and get the count
        result = query_job.result()

        # print('result: ',list(result))

        # Iterate over the rows
        for row in result:
            print(row)

        # Return the count as JSON response
        return {"socialflagcount": row[0]}

    except Exception as e:
        print(e)
        return (
            jsonify({"error": str(e)}),
            500,
        )  # Handle any exceptions and return an error response if needed


""" MASTER ROUTE """


@app.route("/lobmaster")
def lobmaster():
    if "email" in session:
        email = session["email"]
        roles = session.get("roles", [])
        role = session["role"]
        template = session["template"]
        approval = session["approval"]
        verification = session["verification"]

        # print(template.split(','))

        # table_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.LOB_Master"
        # table_id = f"{GCP_PROJECT_ID}.Test.TestLOB"

        LOB_id = f"{GCP_PROJECT_ID}.Easy_Insurance_Master.IRDAI_Master"
        # data = fetch_data(table_id)

        LOB = fetch_LOB(LOB_id)
        # html_table = generate_lob_table(data, LOB)

        # Create a DataFrame from the data
        df = pd.DataFrame(LOB)

        # Convert the DataFrame to a JSON array
        json_array = df.to_json(orient="records")

        # filtered_templatelist = filterTemplateList()

        return render_template(
            "./Master/LOB.html",
            LOBVal=json_array,
            email=email.split("@")[0],
            roles=roles,
            role=role,
            template=template,
            approval=approval,
            verification=verification,
        )
        # return render_template("./Master/LOB.html",html_table=html_table, json_array=json_array, email=email, roles=roles)
    return redirect(url_for("access_denied"))
    # return redirect(url_for('sessiontimeout'))


@app.route("/channelmaster")
def channelmaster():
    if "email" in session:
        email = session["email"]
        roles = session.get("roles", [])
        role = session["role"]
        template = session["template"]
        approval = session["approval"]
        verification = session["verification"]

        # channnel_master = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Channel_Master"
        # channnel_master = f"{GCP_PROJECT_ID}.Test.TestChannel"

        LOB_id = f"{GCP_PROJECT_ID}.Easy_Insurance_Master.IRDAI_Channel"
        # data = fetch_data(channnel_master)
        # print('data: ',data)

        LOB = fetch_LOB(LOB_id)
        # channel_table = generate_channel_table(data, LOB)

        # Create a DataFrame from the data
        df = pd.DataFrame(LOB)

        # Convert the DataFrame to a JSON array
        json_array = df.to_json(orient="records")
        return render_template(
            "./Master/Channel.html",
            channelVal=json_array,
            email=email.split("@")[0],
            roles=roles,
            role=role,
            template=template,
            approval=approval,
            verification=verification,
        )

        # return render_template("./Master/Channel.html",channel_table=channel_table, json_array=json_array, email=email, roles=roles)
    return redirect(url_for("access_denied"))
    # return redirect(url_for('sessiontimeout'))


@app.route("/templatelist")
def getTemplates():
    email = session["email"]
    role = session["role"]
    template = session["template"]

    table_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Report_Master"

    result = fetch_data(table_id)

    # Set up BigQuery client
    client = bigquery.Client()

    """ finalres = pd.DataFrame(result).to_json(orient="records")

    allowedTemp = template.split(",")

    filtered_templatelist = [template for template in finalres if template['Templates'] in allowedTemp]

    print(filtered_templatelist) """

    # Convert the result to a DataFrame
    df = pd.DataFrame(result)

    # Convert the DataFrame to a JSON string
    finalres = df.to_json(orient="records")

    # Parse the JSON string into a list of dictionaries
    finalres_data = json.loads(finalres)

    filtered_templatelist = ""

    if role == "Admin":
        query = f"""
            SELECT DISTINCT(Category) FROM {GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Report_Master
        """
        query_job = client.query(query)

        # Execute the query and get the distinct values
        resultdist = query_job.result().to_dataframe()

        resultJson = pd.DataFrame(resultdist).to_json(orient="records")

        # print(resultJson)
        response_data = {
            "filtered_templatelist": finalres_data,
            "resultJson": resultJson,
        }
        return json.dumps(response_data)
    else:
        templatelist = template.split(",")
        query = f"""
        SELECT DISTINCT(Category) FROM {GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Report_Master where Templates in UNNEST({templatelist})
        """
        # Split the template string into a list
        allowedTemp = template.split(",")

        # Filter the list of dictionaries based on the allowed templates
        filtered_templatelist = [
            template
            for template in finalres_data
            if template["Templates"] in allowedTemp
        ]

        # print(filtered_templatelist)

        # print("finalres: ", finalres, template.split(","))

        global LOB_ACCESS
        global CHANNEL_ACCESS
        global BOTH_ACCESS

        LOB_ACCESS = len(
            list(
                filter(
                    lambda row: row["Master_LOB_Table_Name"] is not None,
                    filtered_templatelist,
                )
            )
        )
        CHANNEL_ACCESS = len(
            list(
                filter(
                    lambda row: row["Master_Channel_Table_Name"] is not None,
                    filtered_templatelist,
                )
            )
        )
        BOTH_ACCESS = len(
            list(
                filter(
                    lambda row: row["Master_LOB_Table_Name"] is not None
                    or row["Master_Channel_Table_Name"] is not None,
                    filtered_templatelist,
                )
            )
        )

        # Print or use the values as needed
        # print(f"LOB_ACCESS: {LOB_ACCESS}")
        # print(f"CHANNEL_ACCESS: {CHANNEL_ACCESS}")
        # print(f"BOTH_ACCESS: {BOTH_ACCESS}")
        
        # Check each variable and set True or False
        lob_result = not (LOB_ACCESS == 0)
        channel_result = not (CHANNEL_ACCESS == 0)
        both_result = not (BOTH_ACCESS == 0)

        # print("LOB_ACCESS:", str(lob_result).lower())
        # print("CHANNEL_ACCESS:", str(channel_result).lower())
        # print("BOTH_ACCESS:", str(both_result).lower())

        query_job = client.query(query)

        # Execute the query and get the distinct values
        resultdist = query_job.result().to_dataframe()

        resultJson = pd.DataFrame(resultdist).to_json(orient="records")

        # print(resultJson)

        response_data = {
            "filtered_templatelist": filtered_templatelist,
            "LOB_ACCESS": LOB_ACCESS,
            "CHANNEL_ACCESS": CHANNEL_ACCESS,
            "BOTH_ACCESS": BOTH_ACCESS,
            "resultJson": resultJson,
        }
        return json.dumps(response_data)
        # return jsonify(response_data)
        # return filtered_templatelist, LOB_ACCESS, CHANNEL_ACCESS, BOTH_ACCESS
        # return filtered_templatelist


@app.route("/uploadmasterdata", methods=["POST"])
def uploadmasterdata():
    print(request.form)
    excelfile = request.files["excelfile"]
    irdaitype = request.form["irdaitype"]
    tablename = request.form["tablename"]
    categorytype = request.form["category"]

    # print(irdaitype,tablename,categorytype)

    # dataset = gettableID()
    filtered_tables = [
        table for table in dataset if table.rsplit(".", 1)[-1] == tablename
    ]
    # print(filtered_tables)

    table_id = pd.Series(filtered_tables).values[0]
    # print(table_id)

    """ LOB_id = (
        f"{GCP_PROJECT_ID}.Easy_Insurance_Master.IRDAI_Master"
        if irdaitype == "lob"
        else f"{GCP_PROJECT_ID}.Easy_Insurance_Master.IRDAI_Channel"
    )
    LOB = fetch_LOB(LOB_id) """

    # Read the Excel file from the request stream using pandas
    excel_data = pd.read_excel(excelfile.stream)

    # Get lists of values from the two columns
    # irdaicol = "IRDAI_LOB" if irdaitype == "lob" else "IRDAI_Channel"

    # excel_irai_lob_values = excel_data[irdaicol].tolist()
    # lob_irai_lob_values = LOB[irdaicol].tolist()

    # Loop through and replace values not present in Lob IRDAI_LOB with blank
    # for i in range(len(excel_irai_lob_values)):
    #     if excel_irai_lob_values[i] not in lob_irai_lob_values:
    #         excel_data.at[i, irdaicol] = ""

    if irdaitype == "lob":
        schema = [
            bigquery.SchemaField("Product_Code", "STRING"),
            bigquery.SchemaField("Company_LOB", "STRING"),
            bigquery.SchemaField(categorytype, "STRING"),
        ]
    elif irdaitype == "socialflag":
        schema = [
            bigquery.SchemaField("Policy_No", "STRING"),
            bigquery.SchemaField("Social_Flag", "STRING"),
        ]
    else:
        schema = [
            bigquery.SchemaField("Company_Channel", "STRING"),
            bigquery.SchemaField("IRDAI_Channel", "STRING"),
        ]

    print(irdaitype)

    # Load the Excel data into BigQuery
    bigquery_table_name = (
        f"{GCP_PROJECT_ID}{table_id}"  # Replace with your BigQuery table name
    )
    job_config = bigquery.LoadJobConfig(
        schema=schema,
        source_format=bigquery.SourceFormat.CSV,
        write_disposition="WRITE_TRUNCATE",
    )

    client = bigquery.Client(project=GCP_PROJECT_ID)
    table_ref = client.get_table(bigquery_table_name)

    # Old Logic
    """
    try:
        with BytesIO() as source_file:
            excel_data.to_csv(source_file, index=False, header=False)
            source_file.seek(0)

            job = client.load_table_from_file(
                source_file, table_ref, job_config=job_config
            )

            job.result()

            if job.state == "DONE":
                resStatus = "True"
                print(f"Excel data uploaded to BigQuery table {bigquery_table_name}.")
            else:
                resStatus = "False"
                print(f"Job did not complete successfully. Job state: {job.state}")
        return resStatus
    except Exception as e:
        print(f"Error: {e}") 
    """
    topic_name = "UseMe"

    # Create a Pub/Sub publisher client
    publisher = pubsub_v1.PublisherClient()

    try:
        with BytesIO() as source_file:
            excel_data.to_csv(source_file, index=False, header=False)
            source_file.seek(0)

            job = client.load_table_from_file(
                source_file, table_ref, job_config=job_config
            )

            job.result()

            if job.state == "DONE":
                resStatus = "True"
                message = f"{table_id}"
                print(message)
                # Publish the message to the specified Pub/Sub topic
                topic_path = publisher.topic_path(GCP_PROJECT_ID, topic_name)
                data = message.encode("utf-8")
                publisher.publish(topic_path, data=data)
            else:
                resStatus = "False"
                print(f"Job did not complete successfully. Job state: {job.state}")

        return resStatus
    except Exception as e:
        print(f"Error: {e}")


# def uploadmasterdata():
#     files = request.files["excelfile"]
#     irdaitype = request.form["irdaitype"]
#     tablename = request.form["tablename"]

#     # print('tablename: ',tablename)

#     dataset = gettableID()

#     filtered_tables = [
#         table for table in dataset if table.rsplit(".", 1)[-1] == tablename
#     ]

#     table_id = pd.Series(filtered_tables).values[0]

#     # print(table_id)

#     folder_path = os.path.join(os.path.expanduser("~"), "Documents")

#     print("Path to Documents folder:", folder_path)

#     # folder_path = 'C:/Users/Laptop_User/Documents/'

#     # Save the uploaded file to the specified folder
#     uploaded_file_path = os.path.join(folder_path, f"{files.filename}")
#     files.save(uploaded_file_path)

#     converted_csv_file_path = convert_xlsx_to_csv(uploaded_file_path)
#     print('converteddata: ',converted_csv_file_path)

#     # Load the CSV data directly into BigQuery
#     # bigquery_table_name = f'{GCP_PROJECT_ID}.Test.TestLOB' if irdaitype == 'lob' else  f'{GCP_PROJECT_ID}.Test.TestChannel' # Replace with your BigQuery table name
#     bigquery_table_name = (
#         f"{GCP_PROJECT_ID}{table_id}"  # Replace with your BigQuery table name
#     )
#     # schema=schema,

#     if irdaitype == "lob":
#         # code block 1
#         schema = [
#             bigquery.SchemaField("Product_Code", "STRING"),
#             bigquery.SchemaField("Company_LOB", "STRING"),
#             bigquery.SchemaField("IRDAI_LOB", "STRING"),
#         ]

#     elif irdaitype == "socialflag":
#         schema = [
#             bigquery.SchemaField("Policy_No", "STRING"),
#             bigquery.SchemaField("Social_Flag", "STRING"),
#         ]

#     else:
#         # code block 3
#         schema = [
#             bigquery.SchemaField("Company_Channel", "STRING"),
#             bigquery.SchemaField("IRDAI_Channel", "STRING"),
#         ]

#     job_config = bigquery.LoadJobConfig(
#         schema=schema,
#         # autodetect=True,  # Enable schema auto-detection
#         source_format=bigquery.SourceFormat.CSV,
#         skip_leading_rows=1,  # Skip the header row
#         write_disposition="WRITE_TRUNCATE",  # Overwrite the table if it exists
#     )

#     client = bigquery.Client(project=GCP_PROJECT_ID)
#     table_ref = client.get_table(bigquery_table_name)

#     try:
#         with open(converted_csv_file_path, "rb") as source_file:
#             # Split the table name into dataset_id and table_id
#             projectID, dataset_id, table_id = bigquery_table_name.split(".")

#             # Get the dataset reference
#             dataset_ref = client.dataset(dataset_id)

#             # Get the table reference within the dataset
#             table_ref = dataset_ref.table(table_id)

#             job = client.load_table_from_file(
#                 source_file, table_ref, job_config=job_config
#             )

#             # Wait for the job to complete
#             job.result()

#             # Check the job's status
#             if job.state == "DONE":
#                 resStatus = "True"
#                 print(
#                     f"File {uploaded_file_path} converted and uploaded to BigQuery table {bigquery_table_name} with schema auto-detection and header row skipped."
#                 )
#             else:
#                 resStatus = "False"
#                 print(f"Job did not complete successfully. Job state: {job.state}")
#         return resStatus
#     except Exception as e:
#         print(f"Error: {e}")


def get_bigquery_table(client, table_id):
    # print('table_id: ',table_id)
    try:
        project_id, dataset_id, table_name = table_id.split(".")
        # print('project_id',project_id)
        dataset_ref = client.dataset(dataset_id)
        table_ref = dataset_ref.table(table_name)
        return client.get_table(table_ref)
    except ValueError:
        print(f"Invalid table_id format. Expected format: dataset_id.table_name")
        return None  # You can choose how to handle this error in your specific use case


# Function to convert XLSX to CSV
def convert_xlsx_to_csv(file_path):
    # print('file_path: ',file_path,os.path.splitext(file_path))
    csv_path = os.path.splitext(file_path)[0] + ".csv"
    df = pd.read_excel(file_path, engine="openpyxl")
    df.to_csv(csv_path, index=False)
    return csv_path


# Old Code
"""
@app.route("/update", methods=["POST"])
def update():
    row_data = flask.request.json
    # print(row_data)
    tablename = row_data["templateJson"]["tablename"]

    dataset = gettableID()

    filtered_tables = [
        table for table in dataset if table.rsplit(".", 1)[-1] == tablename
    ]

    # table_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.LOB_Master" if row_data['irdai'] == 'IRDAI_LOB' else  f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Channel_Master"
    table_id = filtered_tables[0]
    # table_id = filtered_tables[0] if row_data['irdai'] == 'IRDAI_LOB' else  f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Channel_Master"

    result = update_data(table_id, row_data["data"], row_data["irdai"])

    return result
    """


@app.route("/update", methods=["POST"])
def update():
    row_data = flask.request.json
    tablename = row_data["templateJson"]["tablename"]

    # dataset = gettableID()

    filtered_tables = [
        table for table in dataset if table.rsplit(".", 1)[-1] == tablename
    ]

    table_id = f"{GCP_PROJECT_ID}{filtered_tables[0]}"

    # print(table_id)

    result = update_data(table_id, row_data["data"], row_data["irdai"])

    # Your Pub/Sub project ID and topic name
    # project_id = "fine-eye-a"
    project_id = GCP_PROJECT_ID
    topic_name = "UseMe"

    # Create a Pub/Sub publisher client
    publisher = pubsub_v1.PublisherClient()

    # Define the message to be sent
    message = f"{table_id}"

    # Publish the message to the specified Pub/Sub topic
    topic_path = publisher.topic_path(project_id, topic_name)
    data = message.encode("utf-8")
    publisher.publish(topic_path, data=data)

    return result


@app.route("/templatewisetable", methods=["POST"])
def templatewisetable():
    if "email" in session:
        row_data = flask.request.json

        # print(row_data)

        tablename = row_data["tablename"]
        if row_data["irdaiType"] == "LOB":
            category = row_data["category"]
            lobtype = (
                f"{GCP_PROJECT_ID}.Easy_Insurance_Master.IIB_Master"
                if category == "IIB"
                else f"{GCP_PROJECT_ID}.Easy_Insurance_Master.IRDAI_Master"
            )

        # dataset = gettableID()

        filtered_tables = [
            table for table in dataset if table.rsplit(".", 1)[-1] == tablename
        ]

        # print(filtered_tables)

        table_id = f"{GCP_PROJECT_ID}{pd.Series(filtered_tables).values[0]}"

        LOB_id = (
            lobtype
            if row_data["irdaiType"] == "LOB"
            else f"{GCP_PROJECT_ID}.Easy_Insurance_Master.IRDAI_Channel"
        )

        data = fetch_data(table_id)
        # print(data,LOB_id)
        LOB = fetch_LOB(LOB_id)
        # print(table_id)

        df = pd.DataFrame(data)

        # Convert the DataFrame to a JSON array
        json_array = df.to_json(orient="records")

        html_table = (
            generate_lob_all_table(data, LOB, category)
            if row_data["irdaiType"] == "LOB"
            else generate_channel_all_table(data, LOB)
        )

        # print(json_array)

        # return html_table, json_array
        response_data = {"html_table": html_table, "json_array": json_array, "lob_channel": pd.DataFrame(LOB).to_json(orient="records")}

        # print(response_data)

        return jsonify(response_data)

        # return render_template("./Master/LOB.html", html_table=html_table, status='true')
    return redirect(url_for("access_denied"))


""" IRDAI Routes """


def insert_irdai_data(table_id, row_data, irdaiType):
    try:
        client = bigquery.Client()

        if irdaiType == "IRDAI_LOB":
            type = row_data["IRDAI_LOB"]
        else:
            type = row_data["IRDAI_Channel"]
        query = f"SELECT * FROM `{table_id}` WHERE `{irdaiType}` = '{type}'"
        data = client.query(query).to_dataframe()

        if np.array(data).size == 0:
            if irdaiType == "IRDAI_LOB":
                insert_query = f"""
                    INSERT INTO `{table_id}` (IRDAI_LOB) 
                    VALUES ('{row_data["IRDAI_LOB"]}')
                """
            elif irdaiType == "IRDAI_Channel":
                insert_query = f"""
                    INSERT INTO `{table_id}` (IRDAI_Channel) 
                    VALUES ('{row_data["IRDAI_Channel"]}')
                """
            else:
                return "false"
            pandas_gbq.read_gbq(insert_query, dialect="standard")
        else:
            return "exist"
        return "true"
    except Exception as e:
        print("Error:", e)
        return "false"


def update_irdai_data(table_id, row_data, irdaiType):
    # for row in row_data:
    try:
        if irdaiType == "IRDAI_LOB":
            update_query = f"""
                UPDATE `{table_id}`
                SET IRDAI_LOB = '{row_data["IRDAI_LOB"]}'
                WHERE IRDAI_LOB = '{row_data["IRDAI_LOB_old"]}'
            """
        elif irdaiType == "IRDAI_Channel":
            update_query = f"""
                UPDATE `{table_id}`
                SET IRDAI_Channel = '{row_data["IRDAI_Channel"]}'
                WHERE IRDAI_Channel = '{row_data["IRDAI_Channel_old"]}'
            """
        else:
            return "false"
        pandas_gbq.read_gbq(update_query, dialect="standard")
        return "true"
    except Exception as e:
        print("Error:", e)
        return "false"


def generate_irdai_table(data, LOB):
    header = data.columns.values
    irdai_table = "<table id='table1' class='table table-bordered table-hover ' class='display' cellspacing='0' width='100%' style='height: 300px;'>"
    irdai_table += "<thead>"
    irdai_table += "<tr>"
    for elem in header:
        irdai_table += f"<th>{elem}</th>"
    irdai_table += f"<th>Actions</th>"
    irdai_table += "</tr>"
    irdai_table += "<thead>"
    irdai_table += "<tbody>"
    for index, row in data.iterrows():
        irdai_table += "<tr>"
        irdai_table += f"<td IRDAI_LOB='{row['IRDAI_LOB']}' name='IRDAI_LOB'>{row['IRDAI_LOB']}</td>"
        # <button class='btn'><i class='fas fa-trash text-red'></i></button>
        irdai_table += f"<td><button class='btn' onclick='editData(this)' id='editbtn' td_irdai='{row['IRDAI_LOB']}' data-toggle='modal' data-target='#modal-default'><i class='fas fa-edit'></i></button>&nbsp;&nbsp;</td>"
        irdai_table += "</tr>"
    irdai_table += "</tbody>"
    irdai_table += "</table>"
    return Markup(irdai_table)


def generate_irdai_channel_table(data, LOB):
    header = data.columns.values
    irdai_table = "<table id='table1' class='table table-bordered table-hover ' class='display' cellspacing='0' width='100%' style='height: 300px;'>"
    irdai_table += "<thead>"
    irdai_table += "<tr>"
    for elem in header:
        irdai_table += f"<th>{elem}</th>"
    irdai_table += f"<th>Actions</th>"
    irdai_table += "</tr>"
    irdai_table += "<thead>"
    irdai_table += "<tbody>"
    for index, row in data.iterrows():
        irdai_table += "<tr>"
        irdai_table += f"<td IRDAI_Channel='{row['IRDAI_Channel']}' name='IRDAI_Channel'>{row['IRDAI_Channel']}</td>"
        # <button class='btn'><i class='fas fa-trash text-red'></i></button>
        irdai_table += f"<td><button class='btn' onclick='editData(this)' id='editbtn' td_irdai='{row['IRDAI_Channel']}' data-toggle='modal' data-target='#modal-default'><i class='fas fa-edit'></i></button>&nbsp;&nbsp;</td>"
        irdai_table += "</tr>"
    irdai_table += "</tbody>"
    irdai_table += "</table>"
    return Markup(irdai_table)


@app.route("/insertirdai", methods=["POST"])
def insertIrdai():
    row_data = flask.request.json

    table_id = (
        f"{GCP_PROJECT_ID}.Easy_Insurance_Master.IRDAI_Master"
        if row_data["irdaiType"] == "IRDAI_LOB"
        else f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.IRDAI_Channel"
    )

    result = insert_irdai_data(table_id, row_data["data"], row_data["irdaiType"])

    return result


@app.route("/updateirdai", methods=["POST"])
def updateIrdai():
    row_data = flask.request.json
    table_id = (
        f"{GCP_PROJECT_ID}.Easy_Insurance_Master.IRDAI_Master"
        if row_data["irdaiType"] == "IRDAI_LOB"
        else f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.IRDAI_Channel"
    )
    result = update_irdai_data(table_id, row_data["data"], row_data["irdaiType"])
    # print(result)
    return result


@app.route("/irdailob")
def irdailob():
    if "email" in session:
        email = session["email"]
        roles = session.get("roles", [])
        role = session["role"]
        template = session["template"]
        approval = session["approval"]
        verification = session["verification"]

        table_id = f"{GCP_PROJECT_ID}.Easy_Insurance_Master.IRDAI_Master"
        LOB_id = f"{GCP_PROJECT_ID}.Easy_Insurance_Master.IRDAI_Master"

        data = fetch_data(table_id)
        LOB = fetch_LOB(LOB_id)
        irdai_table = generate_irdai_table(data, LOB)

        return render_template(
            "./Irdai Master/Irdailob.html",
            irdai_table=irdai_table,
            email=email.split("@")[0],
            roles=roles,
            role=role,
            template=template,
            approval=approval,
            verification=verification,
        )
    return redirect(url_for("access_denied"))
    # return redirect(url_for('sessiontimeout'))


@app.route("/irdaichannel")
def irdaichannel():
    if "email" in session:
        email = session["email"]
        roles = session.get("roles", [])
        role = session["role"]
        template = session["template"]
        approval = session["approval"]
        verification = session["verification"]

        table_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.IRDAI_Channel"
        LOB_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.IRDAI_Channel"

        data = fetch_data(table_id)
        LOB = fetch_LOB(LOB_id)

        irdai_table = generate_irdai_channel_table(data, LOB)
        return render_template(
            "./Irdai Master/Irdaichannel.html",
            irdai_table=irdai_table,
            email=email.split("@")[0],
            roles=roles,
            role=role,
            template=template,
            approval=approval,
            verification=verification,
        )
    return redirect(url_for("access_denied"))
    # return redirect(url_for('sessiontimeout'))


""" FLASH ROUTE """


def generate_flash_table(data):
    header = data.columns.values
    # print(header)
    html_table = "<table id='table1' class='table table-bordered table-hover' class='display' cellspacing='0' width='100%' style='height: 300px;'>"
    # html_table += "<thead><tr><th>IRDAI_LOB</th><th>Product_Name</th><th>Product_Code</th><th>TOTAL_PREMIUM</th><th>reported_month</th><th>Insurer</th></tr></thead>"
    html_table += "<thead>"
    html_table += "<tr>"
    for elem in header:
        html_table += f"<th>{elem}</th>"
    html_table += "</tr>"
    html_table += "<thead>"
    html_table += "<tbody>"
    # for index, row in data.iterrows():
    #     html_table += "<tr>"
    #     html_table += f"<td>{row['IRDAI_LOB']}</td>"
    #     html_table += f"<td>{row['Product_Name']}</td>"
    #     html_table += f"<td>{row['Product_Code']}</td>"
    #     html_table += f"<td>{row['TOTAL_PREMIUM']}</td>"
    #     html_table += f"<td>{row['reported_month']}</td>"
    #     html_table += f"<td>{row['Insurer']}</td>"
    #     html_table += "</tr>"
    for index, row in data.iterrows():
        html_table += "<tr>"
        for elem in header:
            html_table += f"<td>{row[elem]}</td>"
        html_table += "</tr>"
    html_table += "</tbody>"
    html_table += "</table>"
    html_table += """
        <script src="{{ url_for('static', filename='app.js') }}"></script>
    """
    return Markup(html_table)


def generate_flash_gic_table(data):
    header = data.columns.values

    html_table = "<table id='table1' class='table table-bordered table-hover' class='display' cellspacing='0' width='100%' style='height: 300px;'>"
    # html_table += "<thead><tr><th>IRDAI_LOB</th><th>Product_Code</th><th>TOTAL_PREMIUM</th><th>reported_month</th><th>Insurer</th><th>month_dim</th></tr></thead>"
    html_table += "<thead>"
    html_table += "<tr>"
    for elem in header:
        html_table += f"<th>{elem}</th>"
    html_table += "</tr>"
    html_table += "<thead>"
    html_table += "<tbody>"
    # for index, row in data.iterrows():
    #     html_table += "<tr>"
    #     html_table += f"<td>{row['IRDAI_LOB']}</td>"
    #     html_table += f"<td>{row['Product_Code']}</td>"
    #     html_table += f"<td>{row['TOTAL_PREMIUM']}</td>"
    #     html_table += f"<td>{row['reported_month']}</td>"
    #     html_table += f"<td>{row['Financial_Year']}</td>"
    #     html_table += f"<td>{row['Insurer']}</td>"
    #     html_table += f"<td>{row['month_dim']}</td>"
    #     html_table += "</tr>"
    for index, row in data.iterrows():
        html_table += "<tr>"
        for elem in header:
            html_table += f"<td>{row[elem]}</td>"
        html_table += "</tr>"
    html_table += "</tbody>"
    html_table += "</table>"
    html_table += """
        <script src="{{ url_for('static', filename='app.js') }}"></script>
    """
    return Markup(html_table)


@app.route("/flashfigs")
def flashfigs():
    if "email" in session:
        email = session["email"]
        roles = session.get("roles", [])
        role = session["role"]
        template = session["template"]
        approval = session["approval"]
        verification = session["verification"]
        table_id = (
            f"{GCP_PROJECT_ID}.Easy_Insurance_Premium_Register_Template.Flash_Fig"
        )
        data = fetch_data(table_id)
        flash_table = generate_flash_table(data)
        return render_template(
            "./Flash Figures/Flashfigure.html",
            flash_table=flash_table,
            email=email.split("@")[0],
            roles=roles,
            role=role,
            template=template,
            approval=approval,
            verification=verification,
        )
    return redirect(url_for("access_denied"))
    # return redirect(url_for('sessiontimeout'))


@app.route("/flashfigsgic")
def flashfigs_gic():
    if "email" in session:
        email = session["email"]
        roles = session.get("roles", [])
        role = session["role"]
        template = session["template"]
        approval = session["approval"]
        verification = session["verification"]
        table_id = (
            f"{GCP_PROJECT_ID}.Easy_Insurance_Premium_Register_Template.Flash_Fig_GIC"
        )
        data = fetch_data(table_id)
        flash_gic_table = generate_flash_gic_table(data)
        return render_template(
            "./Flash Figures/Flashfigure_gic.html",
            flash_gic_table=flash_gic_table,
            email=email.split("@")[0],
            roles=roles,
            role=role,
            template=template,
            approval=approval,
            verification=verification,
        )
    return redirect(url_for("access_denied"))
    # return redirect(url_for('sessiontimeout'))


""" Reports ROUTE """


def generate_report_table(data,role):
    header = data.columns.values
    filelist = getReports()

    report_table = "<table id='table1' class='table table-bordered table-hover' class='display' cellspacing='0' width='100%' style='height: 300px;'>"
    report_table += "<thead>"
    report_table += "<tr>"
    report_table += "<th>Templates</th>"
    if role == 'User':
        report_table += "<th>Submit</th>"
    else: 
        report_table += "<th>Approve</th>"
    report_table += "<th>Format</th>"
    # for elem in header:
    #     report_table += f"<th>{elem}</th>"
    # report_table += f"<th>Actions</th>"
    report_table += "</tr>"
    report_table += "<thead>"
    report_table += "<tbody>"

    for index, row in data.iterrows():
        link = row["Report_Link"] if row["Report_Link"] != None else "#"
        capitalize_name = row["Templates"]
        report_table += "<tr>"
        report_table += f"<td name='Templates'><a href={link} id='report-links' target='_blank' style='font-size: 14px;'>{capitalize_name}</a></td>"
        if role == 'User':
            if row['User_approval'] == 'Yes' and  row['Manager_approval'] != 'No':
                report_table += f"<td><span class='text-red'>This report is under review.</span></td>"
            else:
                report_table += f"<td>"
                report_table += f'<label class="switch"><input type="checkbox" user_type="{role}" user_email="{session["email"]}" selected_template="{capitalize_name}" onclick="submitreport(this);">'
                report_table += f'<span class="slider round"></span></label>'
                report_table += f"</td>"
        else:
            if row['Manager_approval'] == 'Yes':
                report_table += f"<td><span class='text-green'>Approved</span></td>"
            else:
                if row['User_approval'] == 'Yes' and  row['Manager_approval'] != 'No':
                    report_table += f"<td align='center'><i id='approve' status='approved' class='fas fa-check-circle text-green' user_type='{role}' user_email='{session['email']}' selected_template='{capitalize_name}' onclick='approvereport(this)'></i><i id='unapprove' status='unapproved' class='fas fa-times-circle text-danger ml-2' onclick='approvereport(this)' user_type='{role}' user_email='{session['email']}' selected_template='{capitalize_name}'></i></td>"
                    # report_table += f"<td>"
                    # report_table += f'<label class="switch"><input type="checkbox" user_type="{role}" user_email="{session["email"]}" selected_template="{capitalize_name}" onclick="approvereport(this);">'
                    # report_table += f'<span class="slider round"></span></label>'
                    # report_table += f"</td>"
                else:
                    report_table += "<td></td>"
                """ report_table += f"<td>"
                report_table += f'<label class="switch"><input type="checkbox" user_type="{role}" user_email="{session["email"]}" selected_template="{capitalize_name}" onclick="approvereport(this);">'
                report_table += f'<span class="slider round"></span></label>'
                report_table += f"</td>" """
        # Check if the row has a matching template in the filelist
        matching_files = [
            flist
            for flist in filelist
            if row["Templates"].lower() == flist["templatename"].lower()
        ]

        # If there are matching files, create a cell with an Excel icon
        if matching_files:
            # report_table += "<tr>"
            for flist in matching_files:
                report_table += f"<td name='Templates'><a href='{flist['fileurl']}' style='cursor: pointer; color: #107c41;'><i class='fas fa-file-excel'></i></a></td>"
            # report_table += "</tr>"
        else:
            # If there are no matching files, create an empty cell with a disabled Excel icon
            # report_table += "<tr>"
            report_table += f"<td name='Templates'><a href='javascript:void(0);' style='pointer-events: none; opacity: 0.4; color: #107c41;'><i class='fas fa-file-excel'></i></a></td>"
            # report_table += "</tr>"

    report_table += "</tbody>"
    report_table += "</table>"
    return Markup(report_table)


def insert_report_data(table_id, row_data):
    try:
        client = bigquery.Client()
        query = f"SELECT * FROM `{table_id}` WHERE Templates = '{row_data}'"
        data = client.query(query).to_dataframe()

        if np.array(data).size == 0:
            insert_query = f"""
                INSERT INTO `{table_id}` (Templates) 
                VALUES ('{row_data}')
            """
            pandas_gbq.read_gbq(insert_query, dialect="standard")
        else:
            return "exist"
        return "true"

    except Exception as e:
        print("Error:", e)
        return "false"


@app.route("/insertreport", methods=["POST"])
def insertreport():
    try:
        excel_file = request.files["excelFile"]
        reportname = request.form["reportname"]
        # result = upload_file_to_gitlab(excel_file, reportname)
        table_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Report_Master"
        result = insert_report_data(table_id, reportname)
        # print(result)
        if result == "true":
            data = upload_file(excel_file, reportname)
            # print('data: ',data.attributes)

        return result
    except Exception as e:
        return f"Error: {str(e)}"


def upload_file(excel_file, reportname):
    GITLAB_HOST = "https://gitlab.com"
    # TOKEN = 'glpat-uZ8T92YMXbr6BrzWCxq3'
    # PROJECT_ID = 34495902 # your project ID

    branch_name = "original-reports"
    TOKEN = "glpat-s_aKYFKWsLkQcJNWwugE"

    # gl = gitlab.Gitlab(GITLAB_HOST, private_token=TOKEN)
    gl = gitlab.Gitlab(GITLAB_HOST)
    project = gl.projects.get(GIT_PROJECT_ID)

    # documents_path = Path.home() / "Documents"

    # print("Path to Documents folder:", documents_path)

    folder_path = os.path.join(os.path.expanduser("~"), "Documents")

    # print("Path to Documents folder:", folder_path)

    # Specify the folder path where the file will be saved
    # folder_path = 'C:/Users/Laptop_User/Documents/'

    # Save the uploaded file to the specified folder
    uploaded_file_path = os.path.join(folder_path, f"{reportname}.xlsx")
    excel_file.save(uploaded_file_path)

    # print(uploaded_file_path)

    with open(uploaded_file_path, "rb") as f:
        bin_content = f.read()
    b64_content = b64encode(bin_content).decode("utf-8")
    # b64_content must be a string!

    # print("b64_content",b64_content)

    result = project.files.create(
        {
            "file_path": f"Reports/{reportname}.xlsx",
            "branch": "original-reports",
            "content": b64_content,
            "author_email": "test@example.com",
            "author_name": "yourname",
            "encoding": "base64",  # important!
            "commit_message": f"Upload file for {reportname}",
        }
    )
    # print('>>>>>>>>',result)

    return result


@app.route("/reports")
def reports():
    if "email" in session:
        email = session["email"]
        roles = session.get("roles", [])
        role = session["role"]
        template = session["template"]
        approval = session["approval"]
        verification = session["verification"]

        # print(template,email)

        # templatelist = template.split(',')
        # Set up BigQuery client
        client = bigquery.Client()

        # Define the BigQuery SQL query to get the count
        if role == "Admin":
            query = f"""
            SELECT DISTINCT(Category) FROM {GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Report_Master
            """
        else:
            templatelist = template.split(",")
            query = f"""
            SELECT DISTINCT(Category) FROM {GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Report_Master where Templates in UNNEST({templatelist})
            """
        table_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Report_Master"

        query_job = client.query(query)
        # Execute the query and get the distinct values
        result = query_job.result().to_dataframe()

        resultJson = pd.DataFrame(result).to_json(orient="records")

        # print(resultJson)

        data = fetch_data(table_id)

        # print(type(data))

        # SELECT DISTINCT(Category) FROM {GCP_PROJECT_ID}.Easy_Insurance_Master.Report_Master`

        if role == "Admin":
            html_table = generate_report_table(data, role)
        else:
            filtered_templatelist = filterTemplateList(data, template)

            # print(pd.DataFrame(filtered_templatelist))

            # print("finalres: ", template.split(","))

            # print(filtered_templatelist)

            html_table = generate_report_table(pd.DataFrame(filtered_templatelist),role)

        return render_template(
            "./Template.html",
            html_table=html_table,
            email=email.split("@")[0],
            roles=roles,
            resultJson=resultJson,
            role=role,
            template=template,
            approval=approval,
            verification=verification,
        )
    return redirect(url_for("access_denied"))
    # return redirect(url_for('sessiontimeout'))


def filterTemplateList(data, template):
    # Convert the result to a DataFrame
    df = pd.DataFrame(data)

    # Convert the DataFrame to a JSON string
    finalres = df.to_json(orient="records")

    # Parse the JSON string into a list of dictionaries
    finalres_data = json.loads(finalres)

    # Split the template string into a list
    allowedTemp = template.split(",")

    # Filter the list of dictionaries based on the allowed templates
    filtered_templatelist = [
        template for template in finalres_data if template["Templates"] in allowedTemp
    ]

    return filtered_templatelist


@app.route("/categorywisetable", methods=["POST"])
def categorywisetable():
    row_data = flask.request.json
    # print(">>>", row_data)

    template = session["template"]
    role = session["role"]

    # table_id = f"{GCP_PROJECT_ID}.user_Oauth.Authentication_copy"
    table_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Report_Master"

    client = bigquery.Client()

    if role == "Admin":
        query = (
            f"SELECT * FROM {table_id} WHERE `Category` = '{row_data}'"
            if row_data != "All"
            else f"Select * from {table_id}"
        )
    else:
        templatelist = template.split(",")
        query = (
            f"SELECT * FROM {table_id} WHERE `Category` = '{row_data}' and Templates in UNNEST({templatelist})"
            if row_data != "All"
            else f"Select * from {table_id} where Templates in UNNEST({templatelist})"
        )

    # print('::::', query)

    data = client.query(query).to_dataframe()

    # print(data)

    html_table = generate_report_table(data,role)

    datajson = pd.DataFrame(data).to_json(orient="records")

    # print(datajson)

    # return html_table, datajson

    response_data = {"html_table": html_table, "datajson": datajson}

    return jsonify(response_data)


@app.route("/subcategorywisetable", methods=["POST"])
def subcategorywisetable():
    row_data = flask.request.json

    # print(">>>", row_data)

    template = session["template"]
    role = session["role"]

    table_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Report_Master"

    client = bigquery.Client()

    if role == "Admin":
        """ query = (
            f"SELECT * FROM {table_id} WHERE `Category` = '{row_data['selectedOpt']}' AND `Sub_Category` = '{row_data['subselectedOpt']}'"
            if row_data["subselectedOpt"] != "All"
            else f"Select * from {table_id} WHERE `Category` = '{row_data['selectedOpt']}'"
        ) """

        if row_data["selectedOpt"] == "All":
            query = f"SELECT * FROM {table_id} WHERE `Sub_Category` = '{row_data['subselectedOpt']}'"
        elif row_data["subselectedOpt"] != "All":
            query = f"SELECT * FROM {table_id} WHERE `Category` = '{row_data['selectedOpt']}' and `Sub_Category` = '{row_data['subselectedOpt']}'"
        else:
            query = f"SELECT * FROM {table_id} WHERE `Category` = '{row_data['selectedOpt']}'"
    else:
        templatelist = template.split(",")
        # query = (
        #     f"SELECT * FROM {table_id} WHERE `Sub_Category` = '{row_data['subselectedOpt']}' and Templates in UNNEST({templatelist})"
        #     if row_data["selectedOpt"] != "All" elif row_data["subselectedOpt"] != "All" f"SELECT * FROM {table_id} WHERE `Category` = '{row_data['selectedOpt']}' and `Sub_Category` = '{row_data['subselectedOpt']}' and Templates in UNNEST({templatelist})"
        #     else f"Select * from {table_id}  WHERE `Category` = '{row_data['selectedOpt']}' and Templates in UNNEST({templatelist})"
        # )

        if row_data["selectedOpt"] == "All":
            query = f"SELECT * FROM {table_id} WHERE `Sub_Category` = '{row_data['subselectedOpt']}' and Templates IN UNNEST({templatelist})"
        elif row_data["subselectedOpt"] != "All":
            query = f"SELECT * FROM {table_id} WHERE `Category` = '{row_data['selectedOpt']}' and `Sub_Category` = '{row_data['subselectedOpt']}' and Templates IN UNNEST({templatelist})"
        else:
            query = f"SELECT * FROM {table_id} WHERE `Category` = '{row_data['selectedOpt']}' and Templates IN UNNEST({templatelist})"
    # print('::::', query)

    data = client.query(query).to_dataframe()

    # print(data)

    html_table = generate_report_table(data,role)

    datajson = pd.DataFrame(data).to_json(orient="records")

    # print(datajson)

    # return html_table, datajson

    response_data = {"html_table": html_table, "datajson": datajson}

    return jsonify(response_data)

@app.route("/submitreports", methods=["POST"])
def submitreports():
    email = session['email']
    row_data = flask.request.json
    
    table_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Report_Master"
    
    client = bigquery.Client()
    
    managerlist = client.query("SELECT email FROM `compliance-reporting-platform.user_Oauth.Authentication` where role = 'Manager'").to_dataframe()
    
    # print(pd.DataFrame(managerlist).to_numpy().flatten())
    
    managerEmail = pd.DataFrame(managerlist).to_numpy().flatten()
    
    templateNames = []
    
    for row in row_data:
        templateNames.append(row['selectedTemplate'])
        query = f"UPDATE `{table_id}` SET User_approval = 'Yes', User = '{row['userEmail']}' where Templates = '{row['selectedTemplate']}'"
        # print(query)
        client.query(query)
    
    client.close()
    
    # print(templateNames,','.join(map(str, templateNames)))
    
    subject = "Compliance Reporting Platform"
    body = f"Hi, Following are the templates that were submitted by {email} for your approval: {','.join(map(str, templateNames))}"
    emaill = ','.join(map(str, managerEmail))
    # send_email(emaill, subject, body)
    
    
    
    return jsonify({"condition": "true", "message": "Report Submitted Successfully"})
    
@app.route("/approvereports", methods=["POST"])
def approvereports():
    email = session['email']
    row_data = flask.request.json
    
    # print(row_data)
    
    table_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.Report_Master"
    
    client = bigquery.Client()
    
    user = client.query(f"SELECT user FROM `{table_id}` where Templates = '{row_data['selectedTemplate']}'").to_dataframe()
    
    print(pd.DataFrame(user).to_numpy().flatten())
    
    userEmail = pd.DataFrame(user).to_numpy().flatten()
    
    # templateNames = []
    
    if(row_data['status']) == 'approved':
        query = f"UPDATE `{table_id}` SET Manager_approval = 'Yes' where Templates = '{row_data['selectedTemplate']}'"
        client.query(query)
        subject = "Compliance Reporting Platform"
        body = f"Hi, template submitted by you has been approved."
        # emaill = ','.join(map(str, managerEmail))
        send_email(userEmail[0], subject, body)
        message = "Report Approved"
        condition = "true"
    else:
        query = f"UPDATE `{table_id}` SET Manager_approval = 'No' where Templates = '{row_data['selectedTemplate']}'"
        client.query(query) 
        subject = "Compliance Reporting Platform"
        body = f"Hi, template submitted by you has been disapproved. Please check the report and submit again"
        # emaill = ','.join(map(str, managerEmail))
        send_email(userEmail[0], subject, body)
        message = "Report Declined"
        condition = "true"
    client.close()
    
    """ for row in row_data:
        templateNames.append(row['selectedTemplate'])
        query = f"UPDATE `{table_id}` SET Manager_approval = 'Yes' where Templates = '{row['selectedTemplate']}'"
        client.query(query)
    
    client.close() """
    
    # print(templateNames,','.join(map(str, templateNames)))
    
    # subject = "Compliance Reporting Platform"
    # body = f"Hi, Following are the templates that were submitted by {email} for your approval: {','.join(map(str, templateNames))}"
    # emaill = ','.join(map(str, managerEmail))
    # send_email(emaill, subject, body)
    
    return jsonify({"condition": condition, "message": message})
  

""" Usermanagement Routes """


def nonecheck(data):
    if data is None:
        return "no"
    else:
        return data


@app.route("/updateusers", methods=["POST"])
def update_users_table():
    data = flask.request.json
    # print(data)
    client = bigquery.Client()
    email = data["email"]
    
    table_id = f"{GCP_PROJECT_ID}.user_Oauth.Authentication"
    if data["usertype"] == "approve":
        query = (
            f"UPDATE `{table_id}` SET approval = 'Yes' WHERE email='{email}'"
        )
        subject = "Account Approved"
        body = f"Hi {email}, your account has been approved. From now on, you can surf our website to explore a lot of interesting things with your account."
        send_email(email, subject, body)
    elif data["usertype"] == "unapprove":
        query = f"UPDATE `{table_id}` SET approval = 'No' WHERE email='{email}'"
        subject = "Account Disapproved"
        body = f"Hi {email}, Thank you for registering your account at our website. Unfortunately, we cannot accept your account."
        send_email(email, subject, body)

    # print(">>", query)

    client.query(query)
    client.close()

    return jsonify({"condition": "true"})


def generate_user_table(data, login_email):
    user_table = "<table id='table1' class='table table-bordered table-hover' class='display' cellspacing='0' width='100%' style='height: 300px;'>"
    user_table += "<thead><tr><th>Email</th><th>Role</th><th>Verification</th><th align='center'>Approve Status</th><th align='center'>Approve</th><th align='center'>Actions</th></tr><thead>"
    user_table += "<tbody>"

    for index, row in data.iterrows():
        # print("false" if (row["approval"] == None or row["approval"] == "No") else "true")
        # user_table += "<td>"
        # if row["email"] != login_email:
        if row["role"] != "Admin":
            user_table += "<td>" + row["email"] + "</td>"

            if row["role"] == None:
                user_table += "<td>None</td>"
            else:
                user_table += "<td>" + row["role"] + "</td>"

            if row["verification"] == None:
                user_table += "<td>Unverified</td>"
            elif row["verification"] == "Yes":
                user_table += "<td>Verified</td>"
            elif row["verification"] == "No":
                user_table += "<td>Unverified</td>"

            if row["approval"] == None or row["approval"] == "No":
                user_table += (
                    f"<td align='center'><span class='text-red'>Unapproved</span></td>"
                )
                # user_table += f"<td><button class='btn btn-success' onclick='updateUsers(this)' user_email='{row['email']}'><i class='fas fa-check-circle'></i></button> <button class='btn btn-danger ml-2' onclick='updateUsers(this)' user_email='{row['email']}'><i class='fas fa-times-circle'></i></button></td>"
                # user_table += f"<td align='center'><i id='approve' class='fas fa-check-circle text-green' data-bs-toggle='tooltip' data-bs-placement='bottom' title='Approve User' onclick='updateUsers(this)' user_type='approve' user_email='{row['email']}'></i> <i id='unapprove' class='fas fa-times-circle text-danger ml-2' data-bs-toggle='tooltip' data-bs-placement='bottom' title='Unapprove User' user_type='unapprove' user_email='{row['email']}' style='pointer-events: none; opacity: 0.4;'></i></td>"
                user_table += f"<td align='center'><button type='button' class='btn btn-block btn-outline-success' data-bs-toggle='tooltip' data-bs-placement='bottom' title='Approve User' onclick='updateUsers(this)' user_type='approve' user_email='{row['email']}'>Approve</button></td>"
            elif row["approval"] == "Yes":
                user_table += (
                    f"<td align='center'><span class='text-green'>Approved</span></td>"
                )
                # user_table += f"<td align='center'><i id='approve' class='fas fa-check-circle text-green' data-bs-toggle='tooltip' data-bs-placement='bottom' title='Approve User' user_type='approve' user_email='{row['email']}' style='pointer-events: none; opacity: 0.4;'></i> <i id='unapprove' class='fas fa-times-circle text-danger ml-2' onclick='updateUsers(this)' data-bs-toggle='tooltip' data-bs-placement='bottom' title='Unapprove User' user_type='unapprove' user_email='{row['email']}'></i></td>"
                user_table += f"<td align='center'><button type='button' class='btn btn-block btn-outline-danger' onclick='updateUsers(this)' data-bs-toggle='tooltip' data-bs-placement='bottom' title='Unapprove User' user_type='unapprove' user_email='{row['email']}'>Unapprove</button></td>"
            # user_table += f"<td align='center'><i id='user-edit' onclick='editemail(this)' user_email='{row['email']}' userrole='{row['role']}' templatelist='{row['template']}' data-toggle='modal' data-target='#modal-default' data-bs-toggle='tooltip' data-bs-placement='bottom' title='Edit User' class='fas fa-user-edit' style='color: #4d6590;'></i></td>"
            user_table += f"<td align='center'><div class='spinner-border' id='spinner-border' role='status' style='color: #4d6590;'><span class='visually-hidden'>Loading...</span></div><i hidden id='user-edit' onclick='editemail(this)' user_email='{row['email']}' userrole='{row['role']}' templatelist='{row['template']}' data-toggle='modal' data-target='#modal-default' data-bs-toggle='tooltip' data-bs-placement='bottom' title='Edit User' class='fas fa-user-edit' style='color: #4d6590;'></i></td>"
            user_table += "</tr>"

    user_table += "</tbody>"
    user_table += "</table>"

    return Markup(user_table)


@app.route("/usermanagment")
def templateuser():
    if "email" in session:
        email = session["email"]
        roles = session.get("roles", [])
        role = session["role"]
        template = session["template"]
        approval = session["approval"]
        verification = session["verification"]

        data = fetch_data(f"{GCP_PROJECT_ID}.user_Oauth.Authentication")
        html_table = generate_user_table(data, email)
        # datajson = pd.DataFrame(data).to_json(orient="records")

        # print("final"+html_table)
        return render_template(
            "./Usermanagement.html",
            html_table=html_table,
            email=email.split("@")[0],
            role=role,
            template=template,
            approval=approval,
            verification=verification,
        )
    return redirect(url_for("access_denied"))


@app.route("/updateuserdata", methods=["POST"])
def updateuserdata():
    row_data = flask.request.json
    templates = row_data["templates"]
    userrole = row_data["userrole"]
    email = row_data["email"]

    # print(templates, userrole, email)

    # Set up BigQuery client
    client = bigquery.Client()

    if userrole == "Admin":
        query = f"""
            Update {GCP_PROJECT_ID}.user_Oauth.Authentication SET role='{userrole}' where email='{email}';
            """
    else:
        query = f"""
            Update {GCP_PROJECT_ID}.user_Oauth.Authentication SET template = '{templates}', role='{userrole}' where email='{email}';
            """

    query_job = client.query(query)

    # print(query_job, query_job.to_dataframe())

    return {"condition": "true", "message": "User Data Updated successfully."}


@app.route("/getuserdata", methods=["POST"])
def getuserdatabyemail():
    row_data = flask.request.json
    email = row_data["email"]

    # Set up BigQuery client
    client = bigquery.Client()

    query = f"""
        SELECT email, template, role, category FROM {GCP_PROJECT_ID}.user_Oauth.Authentication where email='{email}';
        """

    query_job = client.query(query)

    # Create a DataFrame from the data
    # df = pd.DataFrame(query_job)

    # Convert the DataFrame to a JSON array
    # json_array = df.to_json(orient="records")

    # print(json_array)

    result = query_job.result().to_dataframe()
    # print("query_job : ", result)

    # print('result: ', pd.DataFrame(result).to_json(orient="records"))

    json_array = pd.DataFrame(result).to_json(orient="records")

    # print("json: ", json_array)

    response_data = {"condition": "true", "json_array": json_array}

    return json.dumps(response_data)


""" Social Flag Master Routes """


def generate_social_flag(data):
    html_table = "<table id='table1' class='table table-bordered table-hover ' class='display' cellspacing='0' width='100%' style='height: 300px;'>"
    html_table += "<thead><tr><th>Policy No</th><th>Social Flag</th></tr></thead>"
    html_table += "<tbody>"
    html_table += "</td>"
    for index, row in data.iterrows():
        html_table += "<tr>"
        html_table += f"<td>{row['Policy_No']}</td>"
        html_table += f"<td>{row['Social_Flag']}</td>"
        html_table += "</tr>"
    html_table += "</tbody>"
    html_table += "</table>"
    return Markup(html_table)


@app.route("/socialflagmaster")
def socialflagmaster():
    if "email" in session:
        email = session["email"]
        roles = session.get("roles", [])
        role = session["role"]
        template = session["template"]
        approval = session["approval"]
        verification = session["verification"]

        table_id = (
            f"{GCP_PROJECT_ID}.Demo_Master_LOB.Social_Flag_Master"  # Socialflag_Master
        )
        # table_id = f"{GCP_PROJECT_ID}.Test.TestLOB"

        # SELECT Policy_No,count(*) from `{GCP_PROJECT_ID}.Easy_Insurance.easy_insurance_premium_register` where Rural_Social_Flag is null group by Policy_No;

        LOB_id = f"{GCP_PROJECT_ID}.Demo_Easy_Insurance_Master.IRDAI_Master"
        data = fetch_data(table_id)

        LOB = fetch_LOB(LOB_id)

        # client = bigquery.Client()

        # Define the BigQuery SQL query to get the count
        # query = f"""
        #    SELECT Policy_No,count(*) as `Social_Flag` from `{GCP_PROJECT_ID}.Easy_Insurance.easy_insurance_premium_register` where Rural_Social_Flag is null group by Policy_No;
        # """

        # data = client.query(query).to_dataframe()

        # Execute the query and get the count
        # data = query_job.result()

        # print(data)

        html_table = generate_social_flag(data)

        # Create a DataFrame from the data
        df = pd.DataFrame(data)

        # Convert the DataFrame to a JSON array
        json_array = df.to_json(orient="records")

        return render_template(
            "./Master/Socialflag.html",
            html_table=html_table,
            json_array=json_array,
            email=email.split("@")[0],
            roles=roles,
            role=role,
            template=template,
            approval=approval,
            verification=verification,
        )
        # return render_template("./Master/LOB.html",html_table=html_table, json_array=json_array, email=email, roles=roles)
    return redirect(url_for("access_denied"))
    # return redirect(url_for('sessiontimeout'))


""" @app.route("/uploadmsocialflag")
def uploadsocialflagmaster():
    files = request.files['excelfile']
    dataset = gettableID()

    filtered_tables = [table for table in dataset if table.rsplit('.', 1)[-1] == 'Social_Flag_Master']

    table_id = pd.Series(filtered_tables).values[0] """


""" Get Current Month and Previous Month """


@app.route("/getmonthyear")
def getmonthyear():
    currentmonth = f"Select Concat(FORMAT_DATE('%B', Max(Transaction_Date)),' - ',Extract(Year from Max(Transaction_Date))) as Month_Year from `{GCP_PROJECT_ID}.Demo_Easy_Insurance.Premium_Transformed_Data`;"
    # previousmonth = f"Select Concat(FORMAT_DATE('%B', DATE_ADD(Max(Transaction_Date), INTERVAL -1 Month)),' - ',Extract(Year from Max(Transaction_Date))) as Month_Year from `fine-eye-a.Easy_Insurance.easy_insurance_premium_register`;"

    # Create a BigQuery client
    client = bigquery.Client()

    # Run the query to fetch user credentials from BigQuery
    query_current = client.query(currentmonth)
    # query_previous = client.query(previousmonth)
    # print('>>', query_job.result())

    resultCurent = query_current.result()
    # resultPrevious = query_previous.result()

    # print("rows: ", result)

    for crow in resultCurent:
        print(crow)

    """ for prow in resultPrevious:
        print(prow) """

    # Return the count as JSON response
    return {"currentmonthyear": crow[0]}
    # return {"currentmonthyear": crow[0], "previousmonthyear": prow[0]}


if __name__ == "__main__":
    app.run(debug=True)
