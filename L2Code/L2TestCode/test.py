
def aa():
    print("test")

def bb():
    print("gomi")

a = [aa,bb]

b=a[1]()

b=a[0]()

did = {"uuid1": 1, "uuid2": 0}

class ika():
    def __init__(self, did):
        self.did = did
        self.fid = [self.aa, self.bb]

    def aa(self):
        print("a")

    def bb(self):
        print("b")

    def hoge(self, uuid):
        self.fid[self.did[uuid]]()

c = ika(did)

c.hoge("uuid1")

f = lambda x : return if x % 2 == 1 

def kk():
    print("test")

def ll(test):
    print(test)

f = [kk, ll]

class tako():
    def __init__(self, f):
        self.fu = f

    def hoge(self, uuid, test):
        self.fu[uuid](test)

tako(f).hoge(1, "tako")

