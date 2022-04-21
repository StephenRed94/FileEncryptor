class File():
    def __init__(self, name, password, path, isDecrypted, contents):
        self.name = name
        self.password = password
        self.path = path
        self.isDecrypted = isDecrypted
        self.contents = contents
