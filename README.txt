CONTENTS OF THIS FILE
---------------------
   
 * Introduction
 * Requirements
 * Installation/Run/Use
 * Configuration
 * Troubleshooting


INTRODUCTION
------------
The LinkedIn Connection Visualization Application process all the LinkedIn connections of the authenticated user and plots them on a world map.
	
	* For a full description of the application, consult LinkedInVisualization.pdf

REQUIREMENTS
------------
This application requires:

	* Python 2.7
	* Google Chrome 39v

INSTALLATION/RUN/USE
--------------------
	* Run linkedinDemo.py as a normal python file. See https://docs.python.org/2/faq/windows.html#how-do-i-run-a-python-program-under-windows for mpre details.
	* Ensure to include utils.py in the same directory as linkedinDemo.py.
	* After successful completion, you should notice 4 more '.txt ' files in the same directory viz. GeoCodes.txt, Name.txt, Icon.txt and Industry.txt.
	* Open ConnectionsHeatMap.html in Google Chrome browser and browse open GeoCode.txt.
	* Toggle HeatMap twice to generate HeatMap visualization.
	* Open ConnectionsInfoMap.html in Google Chrome browser and browse open GeoCode.txt, Name.txt, Icon.txt and Industry.txt as multiple selection. 	* Geographical Icon visualization will be automatic.

CONFIGURATION
-------------
	* To configure authnticated user, generate set of Keys. See https://developer.linkedin.com/documents/authentication for more details.
	* Replace the set of keys in linkedinDemo.py. This will fetch connections correcponding to the user associated with newly generated keys.
	* To configure Google developer API keys refer https://developers.google.com/console/help/new/#generatingdevkeys.
	* Replace the api_key in linkedinDemo.py.

	Note: Each developer gets 28 days trial period with courtesy restriction of 2.5K requests/day

TROUBLESHOOTING
---------------
	* If the HeatMap is not generated on one button click, ensure that you press it twice:
	* If files other than the ones mentioned are selected, close the browser and reopen the html webpage in a new browser instance.
	* TIP: Before re-running the python program, manually delete GeoCode.txt, Name.txt, Icon.txt and Industry.txt for correct results.

