"""
script grr_automator.py
author: baz
This code automates grr forensic analysis
"""
from grr_api_client import api
from grr_api_client import hunt
import sys



class GrrAutomator():

    server_address = None
    server_user = None
    server_password = None
    grr_api = None
    current_clients = []


    default_client_rate = 2
    default_client_limit = 1
    default_expiry_time = 300

    def __init__(self, server_link=None,user=None,password=None):
        """

        """
        if server_link is None or user is None or password is None:
            raise ValueError("server_link, user and password needs to be provided")

        self.server_address = server_link
        self.server_user = server_link
        self.server_password = server_link


        self.grr_api = api.InitHttp(api_endpoint=self.server_address,
                              auth=(self.server_user, self.server_password)




    def find_client(self, query=None):
        """
        query = "host:name"
        """
        # find all clients
        if query is None:
            query = "."

        search_result = self.grr_api.SearchClients(query)

        result = {}
        for client in search_result:
            # print(client.__dict__)
            client_id = client.client_id
            self.current_clients.append(client_id)
            client_last_seen_at = client.data.last_seen_at
            result[client_id] = client_last_seen_at


    def get_all_clients(self):
        """
        Return all clients
        """
        return self.current_clients


    def create_flow(self, client_id=None, flow_name="FileFinder"):
        """
        Create single flow
        """
        if client_id is None:
            raise ValueError("No client id provided")

        client_obj = self.grr_api.Client(client_id)
        client_obj.CreateFlow(name=flow_name)



    def create_flows_for_all_clients(self, flow_name="FileFinder"):
        """
        Creates flows for all clients
        Default flow name = FileFinder
        """
        main_clients = self.get_all_clients()

        for client_id in ids:
            self.create_flow(client_id=client_id, flow_name=flow_name)




    def create_hunt(self,client_rate=None,client_limit=None,expiry_time=None,flow_name="ArtifactCollectorFlow",artifact_list=["WindowsEventLogs"]):
        """
        Creates hunt
        artifact_list needs to be an array
        """
        if flow_name is None:
            raise ValueError("No flow_name provided")


        if client_rate is not None:
            self.client_rate = client_rate

        if client_limit is not None:
            self.client_limit = client_limit

        if expiry_time is not None:
            self.expiry_time = expiry_time

        hunt_runner_args = grrapi.types.CreateHuntRunnerArgs()

        hunt_runner_args.client_rate = self.default_client_rate
        hunt_runner_args.client_limit = self.default_client_limit
        hunt_runner_args.expiry_time = self.default_expiry_time

        rule = hunt_runner_args.client_rule_set.rules.add()


        flow_args = grrapi.types.CreateFlowArgs(flow_name)

        if flow_name = "ArtifactCollectorFlow":

            if len(artifact_list) == 0:
                raise ValueError("No artifacts provided")

            for art in artifact_list:
                flow_args.artifact_list.append(art)

:


        hunt = grrapi.CreateHunt(flow_name=flow_name, flow_args=flow_args,
                                 hunt_runner_args=hunt_runner_args)
        hunt = hunt.Start()

        # get reference id
        return hunt
