import streamlit as st
import googlemaps
import requests
import re
import hashlib
import time

MAX_ATTEMPTS = 10
LOCK_DURATION = 10

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
google_search_api_key = config.get("GOOGLE_SEARCH_API_KEY", "")
search_engine_id = config.get("SEARCH_ENGINE_ID", "")

st.write("|-------------------------------------|")
st.write("|--------E-mails retrieval Bot--------|")
st.write("|-------------------------------------|\n")

state = st.session_state.get('state', {
    'attempts': 0,
    'password': '',
    'api_choice': '',
    'num_results': 1,
    'search_query': ''
})

if is_user_locked():
    lock_time = int(time.time())
    remaining_time = int((lock_time - int(time.time()) + LOCK_DURATION) / 60)  # Convert remaining time to minutes
    st.write(f"You have exceeded the maximum number of unsuccessful attempts. Please try again after {remaining_time} minutes.")
else:
    if not state['password']:
        state['password'] = st.text_input("Enter password:", value="", type="password", key="password")

    if not verify_password(state['password']):
        state['attempts'] += 1
        st.write("Invalid password.")
        if state['attempts'] >= MAX_ATTEMPTS:
            lock_user()
            st.write("You have exceeded the maximum number of unsuccessful attempts. Your account is locked for 5 minutes.")
    else:
        state['attempts'] = 0  # Reset attempts on successful password entry

        if not state['search_query']:
            state['search_query'] = st.text_input("Enter the search string:", value="", key="search_query")

        if st.button("Search"):
            state['api_choice'] = st.selectbox("Enter '1' to use Google Places API or '2' to use Google Custom Search API:", ('1', '2'), key="api_choice")
            state['num_results'] = st.number_input("How many URLs do you want to get?", min_value=1, step=1, value=1, key="num_results")

            if state['api_choice'] == '1' and google_maps_api_key:
                place_urls = get_place_urls(state['search_query'], state['num_results'], google_maps_api_key)
                print_urls(place_urls)
                proceed = st.selectbox("Do you want to extract email addresses from these URLs?", ('Yes', 'No'))
                if proceed.lower() == "yes":
                    emails = find_email_addresses(place_urls)
                    if emails:
                        st.write("\n\n\n-------- URLs: Email addresses --------\n")
                        for index, (url, email_list) in enumerate(emails.items(), start=1):
                            st.write(f"{index}. {url}: {', '.join(email_list)}\n")
                    else:
                        st.write("No email addresses found.")
                else:
                    st.write("Extraction skipped.")

            elif state['api_choice'] == '2' and google_search_api_key and search_engine_id:
                urls = get_search_results(state['search_query'], state['num_results'], google_search_api_key, search_engine_id)
                print_urls(urls)
                proceed = st.selectbox("Do you want to extract email addresses from these URLs?", ('Yes', 'No'))
                if proceed.lower() == "yes":
                    emails = find_email_addresses(urls)
                    if emails:
                        st.write("--- URLs: Email addresses ---\n")
                        for index, (url, email_list) in enumerate(emails.items(), start=1):
                            st.write(f"{index}. {url}: {', '.join(email_list)}\n")
                    else:
                        st.write("No email addresses found.")
                else:
                    st.write("Extraction skipped.")

            else:
                st.write("Invalid choice or missing API keys. Please check the configuration.")

        state['restart'] = st.selectbox("Do you want to perform another search?", ('Yes', 'No'), key="restart")
        if state['restart'].lower() != "yes":
            state = {}  # Clear the state if user chooses not to perform another search

# Save the state
st.session_state['state'] = state
