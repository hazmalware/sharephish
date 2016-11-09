# sharephish.py

Allows you to share phishing emails from CRITs with a Soltra instance.
Queries the CRITs mongodb for emails with an assigned releasability that you specify and packages them in STIX and sends to Soltra over TAXII. Before using you must create a source in your CRITs and set the variable in the python code, or if you have a pre-existing source you want to use, make sure to change the variable THESOURCE on line 41 of sharephish.py to match your designation. To mark an email for release you simply click the add releasability '+' on the email details page and select your designated source from the list.

This script will query the mongodb for any emails that have been released after 12:00:00 AM local server time to that source.
Parses out email headers, raw body, first attachment, and creates a STIX object packages it wit Cybox/TAXII and sends it to the specified Soltra instance.

NOTE: it does not check to see if the email has been sent previously. if the email has been sent before the script will get a taxii messsage stating the object already exists and will filter it out.

Sets the TLP to Green by default. You can change this by seeting the tlp.color on line 106

You can add 'Analyst Notes' to the stix package description by adding a comment on the email details page and/or attachment details page in CRITs by making the first line of the comment 'ANALYST NOTE'

This gives you the ability to share comments with the Soltra instance but still allowing you to keep your other commnents private

TODO:
- add ability for multiple releasablity sources
- add ability to parse multiple attachments
- create functions to parse any indicators related to the email object in CRITs and ading them as indicators in the stix package


## Installation

requires the following packages
* pymongo==2.8
* cybox==2.1.0.11
* stix==1.1.1.5
* pycurl==7.43.0

you can install manually or pip install -r requirements

This requires that you have set up a source inside your CRITs instance that you want to share with:<br>
CRITs Control Panel -> Items -> Sources from the crits menu<br>
Create a source and set Active=on<br>

Changes that need to be made in the code:
* LINE 41 - Set the variable THESOURCE to the source you created in CRITs OR if you have an existing source you want to use.. make the appropriate changes here
* LINE 68 - Set the variable 'externaltag' to match any tagging you use in the subject line of emails to remove it
* LINE 76 - uncomment this line and add any text you would like to remove from the subject line or body of the email. you can specify multiple terms to remove like so - \bTERM1\b|\bTERM2\b|\bTERM3\b - this will only work for the 'keywords-to-remove' area
* LINE 106 - change the TLP color to suite your needs. it is set to GREEN by default.
* LINE 138 - this will remove internal email addresses that are spoofed as the From, Sender, and Replyto addresses and replace it with the term [SPOOFED]. You can comment and uncomment this section as you see fit. You have to change the 'term1', 'term2' to match your company domains without the .com/.net/etc extensions.


requires a configs.ini file created in the same directory as sharephish.py with the following settings<br>
(make sure to add your information where appropriate)<br>
[MongoConfig]<br>
IP: your-mongodb-ip<br>

[Soltra]<br>
url: your-soltra-taxii-discover-service-url<br>
user: your-soltra-username<br>
pass: your-soltra-password<br>

[CyboxConfig]<br>
url: your-company-url<br>
company: your-company-name-nospaces<br>

place configs.ini and taxiigenerator.py in the same directory as sharephish.py<br>
add your mongodb IP address to the configs.ini<br>
add soltra username/password to the configs.ini<br>
add your company information to the CyboxConfig in configs.ini<br>

## Usage
python sharephish.py

or you can setup crontab to run the sharephish.py on a specified interval


## Credits

created by hazmalware

taxiigenerator.py found on the soltra forums from user sandstad via this forum article:<br>
https://forums.soltra.com/index.php?/topic/480-malware-information-sharing-platform-of-crits/?hl=misp

## License

see license file