from fabric.api import *
from fabric.network import ssh
ssh.util.log_to_file("paramiko.log", 10)
env.hosts = ['164.132.42.156']
env.user = 'root'
env.key_filename = 'C:/Users/Ben/Documents/keys/ovh_rsa_priv.pem'
env.warn_only=True

def local_host():
    local('hostname')

def remote_host():
    run('hostname')

def bro_start(deviceid):
	run('mkdir -p /root/traffic_logs/'+deviceid)
	with cd("/root/traffic_logs/"+deviceid):
		run('timeout 20s bro -i tun0 -C|| true')
		run('python /root/traffic_logs/bro_rf/bro_rf.py /root/traffic_logs/bro_rf/training.log conn.log')

	#print test
    #run('bro -i tun0 -C')
