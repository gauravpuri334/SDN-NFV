app:
	sudo cp sdn/controller.py /opt/ik2220/pox/ext
	sudo /opt/ik2220/pox/pox.py controller
	sudo cp nfv/* /opt/ik2220/click/conf/

clean:
	sudo ps -ef | grep controller | awk '{ print $2 }' | xargs -I processes sudo kill -9 processes
	sudo ps -ef | grep click | awk '{ print $2 }' | xargs -I processes sudo kill -9 processes
