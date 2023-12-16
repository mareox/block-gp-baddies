import logging
import requests
import time
import xml.etree.ElementTree as ET
from lxml import etree

from config import settings

# ------------------------------------------------------------------------------
# Configure logging
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)


# ------------------------------------------------------------------------------
# Ask firewall for last 100 globalprotect logs with authentication failures
# ------------------------------------------------------------------------------
def create_job():
    try:
        # Check if there are trusted users and construct the query part for them
        if settings.panos.trusted_users:
            trusted_users_query = " and ".join(
                [f"( user.src neq '{user}' )" for user in settings.panos.trusted_users]
            )
            query = f"( error eq 'Authentication failed: Invalid username or password' ) and {trusted_users_query}"
        else:
            query = "( error eq 'Authentication failed: Invalid username or password' )"

        url = f"https://{settings.panos.hostname}/api/?key={settings.panos.apikey}&type=log&log-type=globalprotect&nlogs=100&query={query}"
        response = requests.get(url, timeout=10)  # Added timeout
        response.raise_for_status()  # Raise an error for bad status codes
        root = ET.fromstring(response.content)
        return root.find(".//job").text
    except requests.RequestException as e:
        logging.error(f"Network error occurred in check_job_status: {e}")
        return None
    except ET.ParseError as e:
        logging.error(f"XML parsing error occurred in check_job_status: {e}")
        return None


# ------------------------------------------------------------------------------
# check for the status of the job
# ------------------------------------------------------------------------------
def check_job_status(job_id):
    status_url = f"https://{settings.panos.hostname}/api/?key={settings.panos.apikey}&type=log&action=get&job-id={job_id}"
    response = requests.get(status_url)
    root = ET.fromstring(response.content)
    return root.find(".//job/status").text


# ------------------------------------------------------------------------------
# retrieve and parse the results of the job
# ------------------------------------------------------------------------------
def get_job_results(job_id):
    try:
        result_url = f"https://{settings.panos.hostname}/api/?key={settings.panos.apikey}&type=log&action=get&job-id={job_id}"
        response = requests.get(result_url)
        response.raise_for_status()
        return ET.fromstring(response.content)
    except requests.RequestException as e:
        logging.error(f"Network error occurred in get_job_results: {e}")
        return None
    except ET.ParseError as e:
        logging.error(f"XML parsing error occurred in get_job_results: {e}")
        return None


# ------------------------------------------------------------------------------
# extracting the public IPs from the job results
# ------------------------------------------------------------------------------
def extract_public_ips(root):
    return set(
        entry.find("public_ip").text
        for entry in root.findall(".//entry")
        if entry.find("public_ip") is not None
    )


# ------------------------------------------------------------------------------
# generate the xml file of dag entries to add to the firewall
# ------------------------------------------------------------------------------
def generate_xml_file(public_ips, filename="dags.xml"):
    uid_message = etree.Element("uid-message")
    etree.SubElement(uid_message, "type").text = "update"
    register = etree.SubElement(etree.SubElement(uid_message, "payload"), "register")

    for ip in public_ips:
        member = etree.SubElement(
            etree.SubElement(etree.SubElement(register, "entry", ip=ip), "tag"),
            "member",
        )
        member.text = settings.panos.dag_tag

    tree = etree.ElementTree(uid_message)
    tree.write(filename, pretty_print=True, xml_declaration=True, encoding="UTF-8")
    return filename


# ------------------------------------------------------------------------------
# send the generated xml file to the firewall
# ------------------------------------------------------------------------------
def send_xml_to_firewall(xml_filename):
    try:
        url = f"https://{settings.panos.hostname}/api/?type=user-id"
        payload = {"key": settings.panos.apikey}
        with open(xml_filename, "rb") as file:
            files = [("file", (xml_filename, file, "text/xml"))]
            response = requests.request("POST", url, data=payload, files=files)
            response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logging.error(f"Network or API error occurred in send_xml_to_firewall: {e}")
        return None
    except IOError as e:
        logging.error(f"File error in send_xml_to_firewall: {e}")
        return None


def main():
    job_id = create_job()
    if job_id is None:
        logging.error("Failed to create job. Exiting.")
        return

    while True:
        status = check_job_status(job_id)
        if status is None:
            logging.error("Failed to check job status. Exiting.")
            return
        if status == "FIN":
            logging.info("Job completed.")
            break
        else:
            logging.info("Job still processing...")
            time.sleep(3)

    root = get_job_results(job_id)
    if root is None:
        logging.error("Failed to get job results. Exiting.")
        return

    public_ips = extract_public_ips(root)
    xml_filename = generate_xml_file(public_ips)
    response_text = send_xml_to_firewall(xml_filename)
    if response_text is None:
        logging.error("Failed to send XML to firewall. Exiting.")
        return
    logging.info(response_text)


if __name__ == "__main__":
    main()
