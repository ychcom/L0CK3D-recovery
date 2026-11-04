import sys, urllib.request
p = sys.argv[1]
url = sys.argv[2]
d = open(p, 'rb').read()
req = urllib.request.Request(url, data=d, method='PUT')
print(urllib.request.urlopen(req).read().decode())
print('sent %d bytes' % len(d))
