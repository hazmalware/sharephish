#!/usr/bin/env python

import pymongo
from pymongo import MongoClient
from bson.objectid import ObjectId
import datetime
from datetime import date
from stix.core import STIXPackage, STIXHeader
from stix.utils import set_id_namespace
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator
from stix.common import Confidence
from stix.indicator import Indicator, CompositeIndicatorExpression
from stix.ttp import TTP
from cybox.core import Observable
from cybox.objects.file_object import File
from cybox.objects.email_message_object import (EmailMessage, EmailHeader,
                                                Attachments, AttachmentReference)
import ConfigParser
import logging
import logging.handlers
import taxiigenerator
import re

# get all the configs
configs = ConfigParser.ConfigParser()
configs.read('configs.ini')
# mongo configs
dbhost = configs.get('MongoConfig', 'IP')
# cybox namespace configs
companyurl = configs.get('CyboxConfig','url')
companyname = configs.get('CyboxConfig', 'company')

# change this to match the source you want to share phishing emails with and have set up in CRITs
THESOURCE = ''

# create the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# add a debug file handler
fh = logging.handlers.RotatingFileHandler('sharephish.log', maxBytes=2000000, backupCount=2)
fh.setLevel(logging.DEBUG)
# create a formatter and set the formatter for the handler
debugformat = logging.Formatter('%(asctime)s|%(filename)s|%(levelname)s|%(lineno)s|%(funcName)20s()|%(message)s', '%Y-%m-%d %H:%M:%S')
infoformat = logging.Formatter('%(asctime)s|%(filename)s|%(levelname)s|%(lineno)s|%(funcName)20s()|%(message)s', '%Y-%m-%d %H:%M:%S')
fh.setFormatter(infoformat)
# add the handler to the logger
logger.addHandler(fh)

# Create pymongo connection to db
def dbconnect():
	try:
		client = MongoClient(dbhost)
		db = client.crits
		return db
	except Exception, e:
 		logger.error("received error when connecting to mongodb at %s", dbhost, exc_info=True)

def scrubit(item):
	# remove company specific information
	# Remove external email tag from subject line
	externaltag = '[External Email]'
	if externaltag in item:
		item = re.sub(externaltag,'', item)

	# Remove any keywords from relevant areas - change to fit your needs
	# item = re.sub(r'\b<keyword to remove>\b', '<replacement text>', item, flags=re.IGNORECASE)
	return item

def getcomments(db,xid):
	# Check if the email has comments to process
	if db.comments.find({'obj_id':ObjectId(xid)}).count() > 0:
		# get all comments for the current email objectid
		comments = db.comments.find({'obj_id':ObjectId(xid)})
		for comment in comments:
			# check if the comments contain string 'analyst note'
			if comment['comment'].lower().startswith('analyst note'):
				ecomment = re.sub(r'\banalyst note\b', '', comment['comment'], flags=re.IGNORECASE)
	else:
		# no comments
		ecomment = 'none'
	return ecomment	


def createstix(db, themail):
	# Create the stix object
	# Set the cybox namespace
	NAMESPACE = {companyurl : companyname}
	# new ids will be prefixed with your company name
	set_id_namespace(NAMESPACE)

	# Set the TLP color to Green
	marking_specification = MarkingSpecification()
	marking_specification.controlled_structure = "//node() | //@*"	
	
	tlp = TLPMarkingStructure()
	tlp.color = "GREEN"
	marking_specification.marking_structures.append(tlp)
	
	handling = Marking()
	handling.add_marking(marking_specification)
	
	# stix assignments
	stix_package = STIXPackage()
	ttp = TTP(title="Phishing")
	stix_package.add_ttp(ttp)
	stix_package.stix_header = STIXHeader()
	stix_package.stix_header.handling = handling

	# Get data from the email dictionary object
	xid = themail['_id']
	xdate = themail['date']
	xoriginatingip = themail['x_originating_ip']
	xmailer = themail['x_mailer']
	xhelo = themail['helo']
	xfrom = themail['from']
	xsender = themail['sender']
	xreplyto = themail['reply_to']
	xsubject = themail['subject']
	xbody = themail['raw_body']

	# Routines to remove unwanted company identifiers from the emails
	xsubject = scrubit(xsubject)
	xbody = scrubit(xbody)
	
	# Terms to search for in email addresses. 
	# replaces spoofed internal email addresses with [SPOOFED]
	# change to match your company's domain name without the '.com/.net/etc'
	searchterms = ['term1', 'term2']
	for term in searchterms:
		if term.upper() in xfrom.upper():
			xfrom = '[SPOOFED]'
		if term.upper() in xsender.upper():
			xsender = '[SPOOFED]'
		if term.upper() in xreplyto.upper():
			xreplyto = '[SPOOFED]'

	# Remove brackets from xoriginating IP
	xoriginatingip = re.sub(r'\[|\]', '', xoriginatingip)

	# get email comments
	ecomment = getcomments(db,xid)

	# Look for attachment and get info if true
	if themail['relationships']:
		# check if the first relationship is a sample because when an email object with attachment
		# is uploaded to crits the first relationship is always the attachment
		# which is uploaded seperately as a sample and related back to the original email
		if themail['relationships'][0]['type'] in 'Sample':
			myattachment = themail['relationships'][0]['value']
			try:
				myfile = db.sample.find_one({'_id':ObjectId(myattachment)})
				hasattachment = True
						
			except Exception, e:
				logger.error("received error when querying samples collection for email with id %s", xid, exc_info=True)
				hasattachment = False
		else:
			hasattachment = False
	else:
		# no relationships, therefore no attachment
		hasattachment = False

	# Create the combined indicator
	full_email_object = EmailMessage()

	if hasattachment:
		# Get all the file details
		xfilename = myfile['filename']
		xfilesize = myfile['size']
		xfiletype = myfile['filetype']
		xmimetype = myfile['mimetype']
		xmd5 = myfile['md5']
		xsha1 = myfile['sha1']
		xsha256 = myfile['sha256']
		xssdeep = myfile['ssdeep']
		yid = myfile['_id']

		# Check if the attachment has comments to process
		if db.comments.find({'obj_id':ObjectId(yid)}).count() > 0:
			# get all comments for the current attachment objectid
			comments = db.comments.find({'obj_id':ObjectId(yid)})
			for comment in comments:
				# check if the comments contain string 'analyst note'
				if comment['comment'].lower().startswith('analyst note'):
					acomment = re.sub(r'\banalyst note\b', '', comment['comment'], flags=re.IGNORECASE)
		else:
			# no comments
			acomment = 'none'		

		# Create the indicator for just the attachment
		file_attachment_object = EmailMessage()
		file_attachment_object.attachments = Attachments()

		attached_file_object = File()
		attached_file_object.file_name = xfilename
		attached_file_object.file_name.condition = "Equals"
		
		file_attachment_object.add_related(attached_file_object, "Contains", inline=True)
		file_attachment_object.attachments.append(attached_file_object.parent.id_)

		attachdescription = "Phishing email attachment\nFrom: %s\nSubj: %s\n Filename: %s\nSize: %s\nMD5: %s\nSHA1: %s\nSHA256: %s\nSSDEEP: %s\nAnalyst Notes: %s\n"\
												%(xfrom,xsubject,xfilename,xfilesize,xmd5,xsha1,xsha256,xssdeep,acomment)
		indicator_attachment = Indicator(description=attachdescription)
		indicator_attachment.title = "Phishing E-mail Attachment"
		indicator_attachment.add_indicator_type("Malicious E-mail")
		indicator_attachment.observable = file_attachment_object
		indicator_attachment.confidence = "High"		
		full_email_object.attachments = Attachments()
		# Add the previously referenced file as another reference rather than define it again:
		full_email_object.attachments.append(attached_file_object.parent.id_)

	full_email_object.header = EmailHeader()
	full_email_object.header.date = xdate
	full_email_object.header.date.condition = "Equals"
	full_email_object.header.From = xfrom
	full_email_object.header.sender = xsender
	full_email_object.header.sender.condition = "Equals"
	full_email_object.header.reply_to = xreplyto
	full_email_object.header.reply_to.condition = "Equals"
	full_email_object.header.subject = xsubject
	full_email_object.header.subject.condition = "Equals"
	full_email_object.header.x_originating_ip = xoriginatingip
	full_email_object.header.x_originating_ip.condition = "Equals"
	full_email_object.header.x_mailer = xmailer
	full_email_object.header.x_mailer.condition = "Equals"
	full_email_object.raw_body = xbody

	# TODO: Add file hash indicator/observable

	# Create descriptions
	if hasattachment:
		mydescription = "Phishing E-mail - %s\nDate: %s\nSubject: %s\nAttachment: %s\nFrom: %s\nSender: %s\nReply to: %s\nX_Originating_IP: %s\nX_Mailer: %s\nHELO: %s\nRaw Body: \n%s\n\nAnalyst Notes: %s\n\nAttachment Notes:%s\n\n"\
							%(xsubject,xdate,xsubject,xfilename,xfrom,xsender,xreplyto,xoriginatingip,xmailer,xhelo,xbody,ecomment,acomment)
		combined_indicator = Indicator(title="Phishing E-mail - " + xsubject, description=mydescription)

	else:
		mydescription = "Phishing E-mail - %s\nDate: %s\nSubject: %s\nFrom: %s\nSender: %s\nReply to: %s\nX_Originating_IP: %s\nX_Mailer: %s\nHELO: %s\nRaw Body: \n%s\n\nAnalyst Notes: %s\n\n"\
							%(xsubject,xdate,xsubject,xfrom,xsender,xreplyto,xoriginatingip,xmailer,xhelo,xbody,ecomment)
		combined_indicator = Indicator(title="Phishing E-mail - " + xsubject, description=mydescription)

	combined_indicator.add_indicator_type("Malicious E-mail")
	combined_indicator.confidence = Confidence(value="High")
	combined_indicator.observable = full_email_object
	combined_indicator.add_indicated_ttp(TTP(idref=ttp.id_))

	if hasattachment:
		indicator_attachment.add_indicated_ttp(TTP(idref=ttp.id_))		
		stix_package.indicators = [combined_indicator, indicator_attachment]
	else:
		stix_package.indicators = [combined_indicator]

	# Write out stix document for testing
	# try:
	# 	with open('email.xml', 'a') as f:
	# 		f.write(stix_package.to_xml())
	# except Exception, e:
	# 	logger.error("received error when writing stix object to file email.xml for email id %s", xid, exc_info=True)

	# Post data to Soltra Edge over TAXII interface
	setup = {
			"user": configs.get('Soltra', 'user'),
			"password": configs.get('Soltra', 'pass'),
			"url": configs.get('Soltra', 'url')
		}
	try:
		result = taxiigenerator.send_xml(setup, stix_package.to_xml())
		logger.info('Transfer completed of STIX over TAXII interface to Soltra for email with id %s\nGot result of %s', xid, result)
	except Exception, e:
		logger.error('Transfer failed of STIX over TAXII interface to Soltra for email with id %s', xid, exc_info=True)

def main():
	# Get todays date and format for db query
	today = date.today()
	mydate = datetime.datetime(today.year,today.month,today.day)

	# Connect to the CRITs mongodb
	db = dbconnect()

	# Get all emails modified today with specified releasability
	try:
		# returns a pymongo cursor to the emails in the db that we can iterate and not an actual list
		myemail = db.email.find({'modified':{'$gt': mydate},'releasability':{'$elemMatch':{'name':{'$eq':THESOURCE}}}})
		mycount = db.email.find({'modified':{'$gt': mydate},'releasability':{'$elemMatch':{'name':{'$eq':THESOURCE}}}}).count()
	except Exception, e:
		logger.error("received error when querying email collection", exc_info=True)

	logger.info("received %s emails from database to process", mycount)
	
	# Create stix package for each email found	
	for themail in myemail:
		createstix(db, themail)

if __name__ == '__main__':
 	main()