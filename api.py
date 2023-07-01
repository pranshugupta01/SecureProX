import requests
import ssl
import socket
import whois
from datetime import datetime
import os
from flask import Flask,render_template,request, flash,redirect,url_for
from werkzeug.utils import secure_filename 
from flask import jsonify
from waitress import serve
from flask_cors import CORS, cross_origin
import joblib
from pandas import json_normalize
import traceback
from bs4 import BeautifulSoup
import urllib3
# from urllib3.exceptions import HTTPError, URLError


app = Flask(__name__)
CORS(app)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

model = joblib.load("RandomForest_Pickle.pkl") 
print ('Model loaded')
# model_columns = joblib.load("columns.pkl",mmap_mode='r') 


#SFH
def check_sfh(url):
    try:
        response = requests.get(url)
        csp_header = response.headers.get('Content-Security-Policy', '')

        # Check for empty SFH
        if not csp_header:
            return -1
            print("Empty SFH: Server-Side Forwarding (SFH) is not implemented.")

        # Check for SFH pointing to a different domain
        elif "'none'" in csp_header or "'self'" in csp_header:
            return 0
            print("SFH for Different Domain: Server-Side Forwarding (SFH) is implemented, but allows loading content from a different domain.")

        # Check for valid SFH
        elif 'frame-ancestors' in csp_header:
            return 1
            print("Valid SFH: Server-Side Forwarding (SFH) protection mechanism is likely implemented.")
        
        else:
            return -1
            print("Unknown SFH configuration.")

    except requests.exceptions.RequestException:
        return -1

#pop up
def analyze_link_behavior(url):
    response = requests.get(url)
    if response.status_code == 200:
        content_type = response.headers.get('content-type', '')
        if 'html' in content_type:
            html_content = response.text
            if 'oncontextmenu="return false;"' in html_content:
                return -1
                print("Right click Disabled and pop-up")
            else:
                return 1
                print("No pop-up")
        else:
            return 1
            print("No pop-up")
    else:
        return 0
        print("Right click with alert")

#ssl
def check_ssl_final_state(url):
    hostname = url.split('//')[1].split('/')[0] 
    port = 443 
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                if 'https' not in url.lower() and 'http' not in cert['subjectAltName'][0][1].lower():
                    return -1
                    return "Not HTTP nor trusted"
                elif 'http' in url.lower() and 'http' in cert['subjectAltName'][0][1].lower():
                    return 0
                    return "HTTP and trusted"
                elif 'http' in url.lower() and 'http' not in cert['subjectAltName'][0][1].lower():
                    return 1
                    return "HTTP and not trusted"
    except Exception as e:
        return str(e)

#request
def check_request_url(url):
    url_length = len(url)
    threshold = len(url) * 0.22  # 22% threshold

    if url_length > threshold:
        return -1
        print("Request URL > 61%")

    elif threshold <= url_length <= (threshold * 0.61):
        return 0
        print("22% <= Request URL <= 61%")

    else:
        return 1
        print("Request URL < 22%")

#anchor_url
def check_url_of_anchor(anchor_url):
    url_length = len(anchor_url)
    threshold = len(anchor_url) * 0.22  # 22% threshold

    if url_length > threshold:
        return -1
        print("anchor_url > 61%")

    elif threshold <= url_length <= (threshold * 0.61):
        return 0
        print("22% <= anchor_url <= 61%")

    else:
        return 1
        print("anchor_url < 22%")

#check url length
def check_url_length(url):
    url_length = len(url)

    if url_length > 75:
        return -1
        print("len > 75")

    elif 54 < url_length < 75:
        return 0
        print("54 < len < 75")

    else:
        return 1
        print("len < 54")

#domain age
def calculate_domain_age(url):
    try:
        domain = whois.whois(url)
        creation_date = domain.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        current_date = datetime.now()
        domain_age = (current_date - creation_date).days

        if domain_age is not None:
            if domain_age < 365:
                return -1
                print("Age of domain: < 1 year")
        else:
                return 1
                print("Age of domain: > 1 year")

    except Exception as e:
        return 0
        print("Error fetching domain age:", str(e))

    return 0

#IP address
def get_ip_address(url):
    try:
        ip_address = socket.gethostbyname(url)
        if ip_address is not None:
            return 1
            print("URL IP address:", ip_address)
        else:
            return 0
            print("No IP address available.")

        return ip_address
    except socket.gaierror:
        return -1
        return None





# Example usage
url = "https://github.com/nayan911/securehack"
sfh = check_sfh(url)
pop_up = analyze_link_behavior(url)
ssl_final_state = check_ssl_final_state(url)
request_url = check_request_url(url)
url_of_anchor = check_url_of_anchor(url)
url_length = check_url_length(url)
domain_age = calculate_domain_age(url)
ip_address = get_ip_address(url)
web_traffic = 1

query = [sfh,pop_up,ssl_final_state,request_url,url_of_anchor,url_length,domain_age,ip_address,web_traffic]
prediction = model.predict(query)
print(prediction)
# @app.route('/predict', methods=['POST'])
# def predict():
#     if request.method == 'POST':
#         if model:
#             try:
#                 url = request.json
#                 print("HI")
#                 sfh = check_sfh(url)
#                 pop_up = analyze_link_behavior(url)
#                 ssl_final_state = check_ssl_final_state(url)
#                 request_url = check_request_url(url)
#                 url_of_anchor = check_url_of_anchor(url)
#                 url_length = check_url_length(url)
#                 domain_age = calculate_domain_age(url)
#                 ip_address = get_ip_address(url)
#                 web_traffic = 1

#                 # query = pd.get_dummies(pd.DataFrame({'sfh': [sfh],pop_up': [pop_up],'ssl_final_state': [ssl_final_state],'request_url': [request_url],'url_of_anchor': [url_of_anchor],'url_length': [url_length],'domain_age': [domain_age],'ip_address': [ip_address]}))
#                 # query = query.reindex(columns=model_columns, fill_value=0)
#                 query = [sfh,pop_up,ssl_final_state,request_url,url_of_anchor,url_length,domain_age,ip_address]
#                 prediction = model.predict(query)
#                 print(prediction)
#                 return jsonify({'SSID':'SSID','prediction': str(prediction)})
#             except:
#                 return jsonify({'trace': traceback.format_exc()})
#         else:
#             print ('Train the model first')
#             return ('No model here to use')
#     else:
#         "server running, no parameters recieved"

# @app.route('/')
# def home():
#     return "Hello"


# #if __name__  == "__main__":
# #    app.run(host=os.getenv('IP', '0.0.0.0'), 
# #    port=int(os.getenv('PORT', 8889)), debug=True) #any code changes automatic refresh due to debug being True
    
# if __name__ == "__main__":
#     serve(app, host='0.0.0.0',port=8889,threads=2)

    