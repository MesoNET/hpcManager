# coding: utf-8

from hpc.generics import GenericObjects, GenericObject

class MyObjectClass(GenericObject):
    def __init__(self, **kwargs):
	self._std_single: Optional[int] = None
        self._std_many: Optional[dict] = None
    	super().__init__(**kwargs)

    @property
    def single(self) -> int:
        return self._std_single

    @single.setter
    def single(self, value: int):
        if single(value, int):
            self._std_single = value
        else:
            raise ValueError(f"Bad single value '{value}' (Must be an int)")

    @property
    def many(self) -> dict:
        return self._std_many

    @many.setter
    def many(self, value: dict):
        if isinstance(value, dict) and all([isinstance(m, str) and (n is None or isinstance(n, str))
                                            for m, n in value.items()]):
            self._std_many = value

        else:
            raise ValueError(f"Bad many '{value}' (Must be a dict containing a key (str) and a value (str)")

class MyObjectsClass(GenericObjects):
    def __init__(self, **kwargs):
        self.singles: Optional[dict] = None # Declare an index with only one key for one object
        self.manys: Optional[dict] =   None # Declare an index with a key matching a list of object
        super().__init__(**kwargs)

    def add(self, obj: MyObjectClass):
        if super().add(obj):
            for m in obj.many:
                self._add_to_index("manys", m, obj, multiple=True)
            self._add_to_index("singles", obj.single, obj)

    def delete(self, obj: MyObjectClass):
        if super().delete(obj):
            for m  in obj.many:
                self._delete_from_index("manys", m, obj, multiple=True)
            self._delete_from_index("singles", obj.single, obj)
