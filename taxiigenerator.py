import pycurl
import cStringIO
import random
import HTMLParser

def generate_TAXII_header(xml, ssl=True):

		headers = {
				"Content-Type": "application/xml",
				"Content-Length": str(len(xml)),
				"User-Agent": "TAXII Client Application",
				"Accept": "application/xml",
				"X-TAXII-Accept": "urn:taxii.mitre.org:message:xml:1.0",
				"X-TAXII-Content-Type": "urn:taxii.mitre.org:message:xml:1.0",
		}
		if ssl:
				headers["X-TAXII-Protocol"] = "urn:taxii.mitre.org:protocol:https:1.0"
		else:
				headers["X-TAXII-Protocol"] = "urn:taxii.mitre.org:protocol:http:1.0"

		return headers

def taxi_wrapper(xml):

		xmlstart = """<?xml version="1.0" encoding="UTF-8" ?>"""

		boilerplate = """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xsi:schemaLocation="http://taxii.mitre.org/messages/taxii_xml_binding-1.1 http://taxii.mitre.org/messages/taxii_xml_binding-1.1" """

		message_id = str(random.randint(345271,9999999999))

		xml_inbox = xmlstart + """
<taxii_11:Inbox_Message {{boilerplate}} message_id="{{message_id}}">
		<taxii_11:Content_Block>
				<taxii_11:Content_Binding binding_id="{{content_binding}}" />
				<taxii_11:Content>
				{{content_data}}
				</taxii_11:Content>
		</taxii_11:Content_Block>
</taxii_11:Inbox_Message>"""

		xml = xml_inbox.replace('{{boilerplate}}',boilerplate) \
								   .replace('{{message_id}}',message_id) \
								   .replace('{{content_binding}}','urn:stix.mitre.org:xml:1.1.1') \
								   .replace('{{content_data}}', xml )

		return xml

def taxi_poll_xml(feedid):

		xmlstart = """<?xml version="1.0" encoding="UTF-8" ?>"""

		boilerplate = """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xsi:schemaLocation="http://taxii.mitre.org/messages/taxii_xml_binding-1.1 http://taxii.mitre.org/messages/taxii_xml_binding-1.1" """

		message_id = str(random.randint(345271,9999999999))

		xml_poll = xmlstart + """
<taxii_11:Poll_Request {{boilerplate}} message_id="{{message_id}}" collection_name="{{feed_name}}" >
		<taxii_11:Poll_Parameters allow_asynch="false">
				<taxii_11:Response_Type>FULL</taxii_11:Response_Type>
				<taxii_11:Content_Binding binding_id="{{content_binding}}" />
		</taxii_11:Poll_Parameters>
		{{start_end}}
</taxii_11:Poll_Request>"""

		xml = xml_poll.replace('{{boilerplate}}',boilerplate) \
								  .replace('{{message_id}}',message_id) \
								  .replace('{{content_binding}}','urn:stix.mitre.org:xml:1.1.1') \
								  .replace('{{feed_name}}', feedid )

		return xml
#-----------------------------------------


def send_xml(setup, xml, ssl=True):

		taxiixml = taxi_wrapper(xml)
		return send(setup, taxiixml, ssl)

def get_xml(setup, feedid, ssl=True):

		taxiixml = taxi_poll_xml(feedid)
		return send(setup, taxiixml, ssl)

def send(setup, taxiixml, ssl=True):
		headers = [
				"Content-Type: application/xml",
				"Content-Length: " + str(len(taxiixml)),
				"User-Agent: TAXII Client Application",
				"Accept: application/xml",
				"X-TAXII-Accept: urn:taxii.mitre.org:message:xml:1.1",
				"X-TAXII-Content-Type: urn:taxii.mitre.org:message:xml:1.1",
				"X-TAXII-Protocol: urn:taxii.mitre.org:protocol:https:1.0",
		]


		buf = cStringIO.StringIO()

		conn = pycurl.Curl()
		conn.setopt(pycurl.URL, setup["url"])
		conn.setopt(pycurl.USERPWD, "{0}:{1}".format(setup["user"], setup["password"]))
		conn.setopt(pycurl.HTTPHEADER, headers)
		conn.setopt(pycurl.POST, 1)
		conn.setopt(pycurl.TIMEOUT, 999999)
		conn.setopt(pycurl.WRITEFUNCTION, buf.write)
		conn.setopt(pycurl.POSTFIELDS, taxiixml)
		conn.setopt(pycurl.SSL_VERIFYPEER, 0)
		conn.perform()
		hp = HTMLParser.HTMLParser()
		result = hp.unescape(buf.getvalue()).encode('ascii', 'ignore')

		buf.close()
		conn.close()

		return result
