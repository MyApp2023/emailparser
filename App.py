import streamlit as st
import googlemaps
import requests
import re
import hashlib
import time

MAX_ATTEMPTS = 10
LOCK_DURATION = 10
MAX_URLS = 50

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

def verify_password(password):
    hashed_password = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'  #admin
    hashed_input = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password == hashed_input

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
    return results[:num_results]

def get_search_results(query, num_results, api_key, search_engine_id):
    url = f'https://www.googleapis.com/customsearch/v1?key={api_key}&cx={search_engine_id}&q={query}'
    response = requests.get(url)
    data = response.json()
    items = data.get('items', [])
    results = [item['link'] for item in items[:num_results]]
    return results[:num_results]

def find_email_addresses(urls):
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    email_addresses = {}
    for i, url in enumerate(urls, start=1):
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
        if i == MAX_URLS:
            break
    return email_addresses

# Read API keys and search engine ID from config.txt
config = read_config_file()
google_maps_api_key = config.get("GOOGLE_MAPS_API_KEY", "")
google_search_api_key = config.get("GOOGLE_SEARCH_API_KEY", "")
search_engine_id = config.get("SEARCH_ENGINE_ID", "")

# Main program
st.title("Email Parser")

# Track sign-in status using session state
if 'signed_in' not in st.session_state:
    st.session_state.signed_in = False

# Authenticate user
if not st.session_state.signed_in:
    # Prompt for password input
    password_key = get_unique_key()
    password = st.text_input("Enter password:", key=password_key, type="password")
    password = password[:30]  # Limit password length to 30 characters

    # Sign in button
    sign_in_button_key = get_unique_key()
    sign_in = st.button("Sign In", key=sign_in_button_key)

    # Check password and sign in
    if sign_in and password and verify_password(password):
        st.session_state.signed_in = True
        st.success("Authentication successful!")
    elif sign_in and password:
        st.warning("Authentication failed. Please try again.")
        lock_user()

if st.session_state.signed_in:
    st.info("Please enter your search parameters.")

    # Prompt for search input
    search_query_key = get_unique_key()
    search_query = st.text_input("Enter the search string:", key=search_query_key)

    api_choice_key = get_unique_key()
    api_choice = st.selectbox(
        "Select to use Google Businesses or Google Search:",
        ('Google Businesses', 'Google Search'),
        key=api_choice_key
    )

    num_results_key = get_unique_key()
    num_results = st.number_input("How many URLs do you want to get?", min_value=1, max_value=MAX_URLS, step=1, value=1, key=num_results_key)

    # Search and extract e-mails button
    search_emails_button_key = get_unique_key()
    search_emails = st.button("Search and extract e-mails", key=search_emails_button_key)

    if search_query and api_choice and num_results and search_emails:
        if api_choice == 'Google Businesses' and google_maps_api_key:
            st.info("Fetching URLs and e-mails using Google Places API...")
            urls = get_place_urls(search_query, num_results, google_maps_api_key)
            email_addresses = find_email_addresses(urls)
            for i, (url, email_list) in enumerate(email_addresses.items(), start=1):
                st.write(f"\n{i}. {url}\n")
                for email in email_list:
                    st.write(f"- {email}")
        elif api_choice == 'Google Search' and google_search_api_key and search_engine_id:
            st.info("Fetching URLs and e-mails using Google Custom Search API...")
            urls = get_search_results(search_query, num_results, google_search_api_key, search_engine_id)
            email_addresses = find_email_addresses(urls)
            for i, (url, email_list) in enumerate(email_addresses.items(), start=1):
                st.write(f"\n{i}. {url}\n")
                for email in email_list:
                    st.write(f"- {email}")
        else:
            st.error("Missing API key or search engine ID. Please check the configuration.")
    else:
        if not search_query and search_emails:
            st.warning("Please enter a search query.")
else:
    if is_user_locked():
        st.error("Too many failed login attempts. Please try again later.")

# Reset widget keys to avoid duplicate key issue when rerunning the app
widget_counter = 0
