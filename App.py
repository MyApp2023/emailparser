import streamlit as st
import googlemaps
import requests
import re
import hashlib
import time

MAX_ATTEMPTS = 10
LOCK_DURATION = 10

# Counter for generating unique widget keys
widget_counter = 0

def get_unique_key():
    global widget_counter
    widget_counter += 1
    return f"widget_{widget_counter}"

def read_config_file():
    config = {}
    with open("config.txt", "r") as file:
        lines = file.readlines()
        for line in lines:
            key, value = line.strip().split("=")
            config[key] = value
    return config

def verify_credentials(username, password):
    hashed_username = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'  #admin
    hashed_password = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'  #admin
    hashed_input_username = hashlib.sha256(username.encode()).hexdigest()
    hashed_input_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_username == hashed_input_username and hashed_password == hashed_input_password

def lock_user():
    lock_time = int(time.time()) + LOCK_DURATION
    with open("lock.txt", "w") as lock_file:
        lock_file.write(str(lock_time))

def is_user_locked():
    try:
        with open("lock.txt", "r") as lock_file:
            lock_time = int(lock_file.read())
            if lock_time > int(time.time()):
                return True
    except FileNotFoundError:
        pass
    return False

def get_place_urls(query, num_results, api_key):
    gmaps = googlemaps.Client(key=api_key)
    response = gmaps.places(query=query)
    results = []
    for place in response['results']:
        place_details = gmaps.place(place_id=place['place_id'], fields=['website'])
        if 'website' in place_details['result']:
            results.append(place_details['result']['website'])
        if len(results) == num_results:
            break
    return results

def get_search_results(query, num_results, api_key, search_engine_id):
    url = f'https://www.googleapis.com/customsearch/v1?key={api_key}&cx={search_engine_id}&q={query}'
    response = requests.get(url)
    data = response.json()
    items = data.get('items', [])
    results = [item['link'] for item in items[:num_results]]
    return results

def print_urls(urls):
    if len(urls) > 0:
        st.write("\n\n\n-------- URLs --------\n")
        for index, url in enumerate(urls, start=1):
            st.write(f"{index}. {url}\n")
    else:
        st.write("No results found.")

def find_email_addresses(urls):
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    email_addresses = {}
    for url in urls:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                email_matches = re.findall(email_regex, response.text)
                if email_matches:
                    email_addresses[url] = list(set(email_matches))  # Remove duplicates
                else:
                    email_addresses[url] = ['Email not found']  # Add placeholder for email not found
        except requests.exceptions.RequestException as e:
            st.write(f"Error retrieving content from {url}: {e}")
    return email_addresses

# Read API keys and search engine ID from config.txt
config = read_config_file()
google_maps_api_key = config.get("GOOGLE_MAPS_API_KEY", "")
custom_search_api_key = config.get("CUSTOM_SEARCH_API_KEY", "")
search_engine_id = config.get("SEARCH_ENGINE_ID", "")

# Main program
st.title("Email Parser")

# Prompt for username and password input
username_key = get_unique_key()
password_key = get_unique_key()
username = st.text_input("Enter username:", key=username_key)
password = st.text_input("Enter password:", key=password_key, type="password")

# Authenticate user
if username and password and verify_credentials(username, password):
    st.success("Authentication successful!")
    st.info("Please enter your search parameters.")
    
    # Prompt for search input
    search_query_key = get_unique_key()
    search_query = st.text_input("Enter the search string:", key=search_query_key)
    
    api_choice_key = get_unique_key()
    api_choice = st.selectbox("Enter '1' to use Google Places API or '2' to use Google Custom Search API:", ('1', '2'), key=api_choice_key)
    
    num_results_key = get_unique_key()
    num_results = st.number_input("How many URLs do you want to get?", min_value=1, step=1, value=1, key=num_results_key)
    
    if search_query and api_choice and num_results:
        if api_choice == '1' and google_maps_api_key:
            st.info("Fetching URLs from Google Places API...")
            urls = get_place_urls(search_query, num_results, google_maps_api_key)
            print_urls(urls)
            email_addresses = find_email_addresses(urls)
            st.write("\n\n\n-------- Email Addresses --------\n")
            for url, email_list in email_addresses.items():
                st.write(f"\n{url}\n")
                for email in email_list:
                    st.write(f"- {email}")
        elif api_choice == '2' and custom_search_api_key and search_engine_id:
            st.info("Fetching URLs from Google Custom Search API...")
            urls = get_search_results(search_query, num_results, custom_search_api_key, search_engine_id)
            print_urls(urls)
            email_addresses = find_email_addresses(urls)
            st.write("\n\n\n-------- Email Addresses --------\n")
            for url, email_list in email_addresses.items():
                st.write(f"\n{url}\n")
                for email in email_list:
                    st.write(f"- {email}")
        else:
            st.error("Missing API key or search engine ID. Please check the configuration.")
else:
    if is_user_locked():
        st.error("Too many failed login attempts. Please try again later.")
    elif username and password:
        st.warning("Authentication failed. Please try again.")
        lock_user()

# Reset widget keys to avoid duplicate key issue when rerunning the app
widget_counter = 0
