



import re #regular expressions



class cRegexSearcher:
    """Processes inputstring for regex matches"""
    #class instantiator
    def __init__(self, input_string):
        self.input = input_string.strip()  
        #instantiate dictionary object for storing regexex & matches
        self.matches = dict()
        self.regexes = dict()
    #define regular expression pattern strings
    ##########################################
        try:
            #RFC 821 email addresses
            self.regexes['email'] = re.compile(r"(\b[a-z0-9]([a-z0-9\._%+\-]+)?(@|\[at\]|\[@\]|\(at\)|\(@\)|<at>|<@>)([a-zA-Z0-9][a-zA-Z0-9\-<>]+(\.|\[\.\]|\[dot\]|\(dot\)|\(\.\)|<dot>|<\.>))+((com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|(co\.uk))|(ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|(ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|(\[(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.|\[\.\]|\[dot\]|\(dot\)|\(\.\)|<dot>|<\.>)(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.|\[\.\]|\[dot\]|\(dot\)|\(\.\)|<dot>|<\.>)(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.|\[\.\]|\[dot\]|\(dot\)|\(\.\)|<dot>|<\.>)(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\]))\b)", re.I)

            #Fully Qualified Domain Names
            self.regexes['fqdn'] = re.compile(r"(([a-zA-Z0-9][a-zA-Z0-9\-]+(\.|\[\.\]|\[dot\]|\(dot\)|\(\.\)|<dot>|<\.>))+(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|(co\.uk)|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bl|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)(\b|$))", re.I)

            #Net Range 
            self.regexes['netrange'] = re.compile(r"\b(((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])(\.|\[\.\]|\[dot\]|\(dot\)|\(\.\)|<dot>|<\.>)(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.|\[\.\]|\[dot\]|\(dot\)|\(\.\)|<dot>|<\.>)(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.|\[\.\]|\[dot\]|\(dot\)|\(\.\)|<dot>|<\.>)(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])) - ((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])(\.|\[\.\]|\[dot\]|\(dot\)|\(\.\)|<dot>|<\.>)(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.|\[\.\]|\[dot\]|\(dot\)|\(\.\)|<dot>|<\.>)(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.|\[\.\]|\[dot\]|\(dot\)|\(\.\)|<dot>|<\.>)(25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])))\b", re.I)

            #cidr 
            self.regexes['cidr'] = re.compile(r"\b(([0-9]{1,3}\.){3}[0-9]{1,3}($|/(\d\d)))\b", re.I)
        except Exception, err:
            raise err

        #find all regex matches in file text, populate dictionary, and return count
        self.matchcount = self.regexSearch()
        #check input for key matches/counts
    

    def regexSearch(self):
        """performs regular expression search of file text""" 
        #instantiate match counter
        mcount = 0
        match_list = []
        if not self.input == "":
            for rtype in self.regexes.keys():
                try:
                    rgx = self.regexes[rtype]
                    rmatches = rgx.findall(self.input)
                    for match in rmatches:
                        mcount = mcount+1
                        if type(match) == tuple:
                            _tmpstring = match[0]                        
                        else:
                            _tmpstring = match
                        # assumes 3d or 3c are hex values,remove first 2 charcaters
                        if rtype == "email" and (_tmpstring.lower().startswith("3d") or
                            _tmpstring.lower().startswith("3c")):
                            #remove first 2 characters from string
                            _tmpstring = _tmpstring[2:]
                        #lowercase non url & filepath matches
                        if not rtype=="url" and not rtype == "filepath":
                            _tmpstring = _tmpstring.lower()
                        #trim usergaent strings
                        if rtype=="useragent":
                            _tmpstring = re.sub(r'user-agent:\s+','',_tmpstring)
                            _hstndx = -1
                            try:
                                _hstndx = _tmpstring.index("host:")
                                #check for 'accept' 
                                _acptndx = _tmpstring.index("accept:")
                                if _acptndx >= 0 and _hstndx >= 0 and _acptndx < _hstndx:
                                    _hstndx = _acptndx
                            except:
                                pass
                            if _hstndx >= 0:
                                _tmpstring = _tmpstring[:_hstndx].strip()
                        #Add to match dictionary
                        _curcount = 0
                        if _tmpstring in self.matches:
                            _curcount = self.matches[_tmpstring][1]
                            #print _tmpstring
                            match_list.append([_tmpstring,rtype])
                    
                        self.matches[_tmpstring] = [rtype,_curcount+1]   
                        continue                     
                except Exception, err:
                    raise err
                    
        #return number of regex matches
        return match_list

