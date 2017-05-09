#ABSA using ABD from Android SDK
import os.path as op
import subprocess
import fabric
from multiprocessing import Process
from multiprocessing import Pool

dir_path = op.dirname(op.realpath(__file__))

def checksdk():
    #Check if Android SDK exists
    if op.exists('c:/platform-tools/') != True:
        print 'Android SDK not found in default path, please install (or specify path?)'
        exit()
    else:
        print 'Android SDK found'

def checkattached():
    #Check if device has accepted host fingerprint
    output = subprocess.check_output(["c:/platform-tools/adb.exe", "devices", "-l"])
    print output
    
    if 'unauthorized' in output:
        print '--Device must be authorised for USB debugging. Authorise and restart'
        exit()
    elif 'product' in output:
        print '--Device authorized for USB debugging'
        print '--Testing started'
        return output
    else:
        print '--Device must be attached for USB debugging'
        exit()

def settings(out):
    #Check Android Version and Security patch level
    versions = subprocess.check_output(["c:/platform-tools/adb.exe", "shell", "getprop"])
    out2 = out.find('model')
    model = out[(out2+6):(out2+14)]
    #print versions
    #Cut version numbers
    a_version = 'ro.build.version.release'
    s_version = 'ro.build.version.security_patch'
    f_version = 'ro.build.display.id'
    #m_v = out.find('model')
    a_v = versions.find(a_version)
    s_v = versions.find(s_version)
    f_v = versions.find(f_version)
    firm = versions[(f_v+23):(f_v+29)]
    #print m_v
    print ('Model: ' + model)
    print ('Firmware: ' + firm)
    print ('Android version: ' + versions[(a_v+28):(a_v+33)])
    print ('Android security patch level: ' + versions[(s_v+35):(s_v+45)])
    
    # Check SELinux is enabled
    selinux = subprocess.check_output(["c:/platform-tools/adb.exe", "shell", "getenforce"])
    if 'Enforcing' in selinux:
        print 'SElinux Enforced.'
    
    elif 'Permissive' in selinux:
        print 'SElinux Permissive mode detected'

    return model, firm
def analyse_apps():
    #list packages
    versions = subprocess.check_output(["c:/platform-tools/adb.exe", "shell", "pm list packages"])
    #put each package in a list with the 'package:' removed
    packages = []
    for v in versions.splitlines():
        packages.append(v[8:])
    dirs = []
    #pool with 8 threads
    P = Pool(8)
    #find directory for each package
    dirs = P.map(dirfind, packages)
    #pull apk for each directory
    names = P.map(pullapk, dirs)
    print str(len(names)) + " applications pulled"
    #extract manifest for each apk
    manifests = dict(P.map(extractmanifest, names))
    #parse permissions from each manifest
    perms = dict(map(lambda names, manifests:(names, manifests.count("uses-permission")), manifests.iteritems()))
    #print manifests[1]
    print perms
    print "all apks extracted for analysis"
    print 'RUNNING'

def dirfind(package): # will return path of the apk from the package name
    path = subprocess.check_output(["c:/platform-tools/adb.exe", "shell", "pm", "path", package])
    path = path[8:-2]
    return path
#def pull_ca_certs():
    #adb pull /system/etc/security/cacerts/
    #

def pullapk(apk): # will pull the apk off the device using path
    name = apk.replace('/', '_')
    pull = subprocess.check_output(["c:/platform-tools/adb.exe", "pull", apk, "c:/Users/Ben/Documents/final year project/code/apks/"+name])
    return name

def extractmanifest(name): # will extract the manifest.xml file contents using aapt.exe and return tuple name, manifest
    manifest = subprocess.check_output([dir_path+"/aapt.exe", "l", "-a", dir_path+"/apks/"+name])
    return name, manifest

"""def parsemanifest(man, name):
    count = []
    name = name.replace('/', '_')
    count = man.count("uses-permission")
    perms = {name:count}
    return perms"""

def network_analysis(model, firm):
    start_bro = subprocess.check_output(["C:/Python27/Scripts/fab.exe", "-f", dir_path+"/fabfile.py", "bro_start:"+model+firm])
    print start_bro
    print "Retreiving Network Analysis results"
    #subprocess.call(["pscp", "-load", "ovh", "root@164.132.42.156:/root/traffic_logs/bro_rf/results.txt", "c:/Users/Ben/Documents/final year project/code/results.txt"])
    print 'Network analysis complete'
    """def get_results()

    t = Timer(30.0, getresults)
    t.start() # after 30 seconds function will be ran"""
if __name__ == '__main__':
    checksdk()
    out = checkattached()
    print "--Starting settings analysis"
    model, firm = settings(out)
    print "--Starting network analysis"
    #p1 = Process(target=network_analysis,args=(model, firm))
    #p1.start()
    print "--Starting application analysis"
    p2 = Process(target=analyse_apps)
    p2.start()
