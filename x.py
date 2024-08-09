import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import pandas as pd
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_emails_from_text(text):
    """Extract emails from a text using regex."""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(email_pattern, text)

def get_all_links(url, soup):
    """Get all unique, complete links from a BeautifulSoup object."""
    links = set()
    for a_tag in soup.find_all('a', href=True):
        link = urljoin(url, a_tag['href'])
        parsed_link = urlparse(link)
        if parsed_link.scheme in ["http", "https"]:
            links.add(link)
    return links

def scrape_emails_from_page(url):
    """Scrape emails from a single web page."""
    try:
        logger.info(f"Scraping URL: {url}")
        response = requests.get(url)
        response.raise_for_status()  # Check for request errors
        soup = BeautifulSoup(response.text, 'html.parser')
        emails = get_emails_from_text(soup.get_text())
        logger.info(f"Found emails: {emails}")
        return emails, soup
    except requests.RequestException as e:
        logger.error(f"Request failed: {e}")
        return [], None

def scrape_emails_website(start_url, max_depth=2):
    """Scrape emails from a website up to a certain depth."""
    visited_urls = set()
    urls_to_visit = {start_url}
    all_emails = set()
    email_data = []

    for depth in range(max_depth):
        if not urls_to_visit:
            break

        new_urls_to_visit = set()
        for url in urls_to_visit:
            if url not in visited_urls:
                visited_urls.add(url)
                emails, soup = scrape_emails_from_page(url)
                for email in emails:
                    email_data.append((url, email))
                all_emails.update(emails)
                if soup:
                    new_urls_to_visit.update(get_all_links(url, soup))

        urls_to_visit = new_urls_to_visit - visited_urls

    return email_data

def save_emails_to_excel(email_data, filename='emails.xlsx'):
    """Save email data to an Excel file."""
    df = pd.DataFrame(email_data, columns=['URL', 'Email'])
    df.to_excel(filename, index=False)
    logger.info(f"Emails saved to {filename}")

# Example usage
start_url = "https://search.emis.gov.eg/search_schpriv.aspx"  # Change this to your target URL
email_data = scrape_emails_website(start_url)
save_emails_to_excel(email_data, 'emails.xlsx')
print("Found emails:", email_data)
