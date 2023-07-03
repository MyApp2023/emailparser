import streamlit as st
import googlemaps
import requests
import re
import hashlib
import os

MAX_ATTEMPTS = 5

def read_config_file():
    config = {}
    with open("config.txt", "r") as file:
        lines = file.readlines()
        for line in lines:
            key, value = line.strip().split("=")
            config[key] = value
    return config

def verify_password(password):
    hashed_password = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'  # admin
    hashed_input = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password == hashed_input

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
st.write("|      Welcome to Email Parser        |")
st.write("|-------------------------------------|")

def login():
    authenticated = False

    while not authenticated:
        # Prompt for password input
        password = st.text_input("Enter password:", type="password", key="password_input")
        password = password[:30]  # Limit password length to 30 characters

        if not verify_password(password):
            st.write("Invalid password.")
        else:
            authenticated = True

    query = st.text_input("Enter your query:")
    num_results = st.number_input("Enter the number of results to retrieve:", min_value=1, step=1, value=5)

    st.write("\nRetrieving place URLs from Google Maps...")
    place_urls = get_place_urls(query, num_results, google_maps_api_key)
    st.write("\nRetrieving search URLs from Google Custom Search...")
    search_urls = get_search_results(query, num_results, google_search_api_key, search_engine_id)

    all_urls = place_urls + search_urls
    print_urls(all_urls)

    st.write("\n\n\n-------- Email Addresses --------\n")
    email_addresses = find_email_addresses(all_urls)
    for url, email_list in email_addresses.items():
        st.write(f"\nURL: {url}")
        st.write("Emails:")
        for email in email_list:
            st.write(email)

login()
