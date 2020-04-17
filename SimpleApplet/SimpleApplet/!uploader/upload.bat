REM uninstall previously loaded applet 
java -jar gp.jar -uninstall SimpleApplet.cap

REM load new version
java -jar gp.jar -install SimpleApplet.cap -verbose -d

REM list available applets 
java -jar gp.jar -l


