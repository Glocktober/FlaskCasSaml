import json

class URNmanager:
    """ Mange white lists of URNs/URIs """       

    def __init__(self, filepath=None):
        """ Load (optional) service limits file. """
        
        # note: not in current_app context
        self.urn_list = None
        if filepath:
            # open and load json list of authorized service URNs
            try:
                with open(filepath,'r') as f:
                    self.urn_list =  json.load(f)
                    print(f'*** Loaded service validation list {filepath}',file=sys.stderr)

            except Exception as e:
                # specified file could either not be open and read or the json loaded
                print(f'ERROR: Exception in init_service_urn for file "{filepath}": {str(e)}', file=sys.stderr)
                raise e


    def valid(self, service):
        """ Validate a service is on the approved list. """

        if service and self.urn_list:
            # Find matching service
            for aservice in self.urn_list:
                if self.match(aservice, service):
                    return service
        else:
            # promiscuous approval of service
            return service

        # service is not authorized
        return None
    

    def match(self, standard_urn, test_urn):
        """ Compare the test_urn against the standard_urn. """

        # case insensitive match
        standard = standard_urn.lower()
        test = test_urn.lower()

        # match if the test_urn begins with the stadard_urn
        #  - this allows subtree URLs and querystrings in the service
        # change if more specific test needed (e.g. test_urn == standard_urn)
        return test.startswith(standard)
