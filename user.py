class User():
    def __init__(self, id, name):
        self._id = id
        self._name = name

    def get_name(self):
        return self._name
    def __del__(self):
        del self

class Admin(User):
    def __init__(self,id:int,name:str,department:str,position:str,salary:float,manager:bool,contact:int,rating:float):
        super().__init__(id,name)
        self._department = department
        self._pos = position
        self._salary = salary
        self._manager = manager
        self._contact= contact
        self.rating = rating

class Client(User):
    def __init__(self,id:int, name:str, email:str, card:int, membership:bool, points:int):
        super().__init__(id,name)
        self._email = email
        try:
            self._cardno = card[:15]
            self._cvv = card[15:]
        except:
            self._cardno = None
            self._cvv = None
        self._membership = membership
        self._points = points