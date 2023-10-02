# 
# This file is part of the Fedstellar platform (see https://github.com/enriquetomasmb/fedstellar).
# Copyright (c) 2023 Chao Feng.
#
from fedstellar.learning.aggregators.aggregator import Aggregator
from fedstellar.learning.aggregators.helper import cosine_similarity
from fedstellar.learning.modelmetrics import ModelMetrics
from fedstellar.learning.pytorch.lightninglearner import LightningLearner
from fedstellar.learning.aggregators.helper import normalise_layers
from statistics import mean
from typing import List, Dict, OrderedDict, Set
import math
import copy
import torch
import collections
import logging
import random

# COSINE_FILTER_THRESHOLD = float(0.5)
# NODES_THRESHOLD= float(0.5)

class Voyager():
    """
    Voyager
        MTD-based aggregation
    """
    def __init__(self, 
                 config,
                 node_threshold=0.75,
                 distance_threshold=3,                 
                 with_reqution=False
                 ):
        self.config = config
        self.distance_threshold = distance_threshold
        self.node_threshold = node_threshold
        self.with_reqution = with_reqution
        matrix = config['matrix']
        malicious = self.get_malicious(config['attack_matrix'])
        converted_matrix = self.incidence_matrix_to_dictionary(matrix)
        adjusted_dictionary = self.number_efficient(converted_matrix, self.node_threshold, self.distance_threshold, malicious , self.with_reqution)
        self.reconverted_matrix = self.convert_dictionary_to_incidence_matrix(adjusted_dictionary)
        
    def get_malicious(self, attack_matrix):
        malicious_list = []
        for i in attack_matrix:
            if i[1]!='No Attack':
                malicious_list.append(str(i[0]))
        return malicious_list


    def calculating_neighbors(self, graph, root, desired_distance, threshold):
        # considered is a list of nodes considered for aggregation

        considered = []
        # variables for finding distance
        depth = 0
        time_to_depth_increase = 0
        pending_depth_increase = False
        check = False
        # start
        visited = set()
        queue = collections.deque([root])
        visited.add(root)

        # numbers of new connections made for this specific node
        connections = 0
        # if the node has no neighbors then the graph is not connected, so we return 0 as there is nothing to do
        if len(graph[root]) == 0:
            return connections

        # main loop
        while queue:

            if time_to_depth_increase != 0:
                time_to_depth_increase -= 1

            if time_to_depth_increase == 0:
                depth += 1
                pending_depth_increase = False

            vertex = queue.popleft()

            # If not visited, mark it as visited, and enqueue it

            for neighbour in graph[vertex]:
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append(neighbour)

            # Append the nodes with desired distance

            if depth == desired_distance and check:
                for i in range(0, len(queue)):
                    if queue[i] not in considered and (len(graph[root]) + len(considered)) < threshold:
                        # when adding to the neighbor list then we also increase the edges by one
                        connections += 1
                        considered.append(queue[i])
                break
            check = True

            if not pending_depth_increase:
                time_to_depth_increase = len(queue)
                pending_depth_increase = True

        # print("neighbors of distance " + str(desired_distance) + " to current node: ")
        # print(considered)
        graph[root].extend(considered)
        #print("visited:")
        #print(visited)
        return connections

    def number_efficient(self, graph, percentage, distance, malicious_list, with_repution):
        #print("original graph:")
        #print(graph)
        # set the threshold required for all nodes'
        threshold = round(percentage * len(graph))
        # threshold = 3

        distance = distance

        # calculating total of new connections made in the whole graph

        connections = 0

        # if not enough nodes then add nodes of k-distance

        for node in graph:
            if with_repution and node in malicious_list:
                continue
            considered = []
            if len(graph[node]) < threshold:
                connections = connections + self.calculating_neighbors(graph, node, distance, threshold)

            # if there is still not enough node after adding then add random. this can be changed to anything if desired
            
            not_in_list = [i for i in graph.keys() if i not in graph[node]]
            # print(node, not_in_list, graph[node])
            while len(graph[node]) + len(considered) < threshold and len(not_in_list) > 0:
                to_be_added = random.choice(not_in_list)
                
                if with_repution:
                    if to_be_added not in graph[node] and to_be_added != node and to_be_added not in malicious_list:
                        graph[node].append(to_be_added)
                        connections += 1
                        # print(f"to be added: {node} -> {to_be_added}")
                        # print(type(to_be_added))
                        # print(type(node))
                else:
                    if to_be_added not in graph[node] and to_be_added != node:
                        graph[node].append(to_be_added)
                        connections += 1
                not_in_list.remove(str(to_be_added))
        #print("new graph")
        #print(graph)
        #print("total connections new:")
        #print(connections)
        return graph


    def incidence_matrix_to_dictionary(self, matrix):
        converted_matrix = {}
        for i in range(len(matrix)):
            converted_matrix[str(i)] = matrix[i]

        # convert to strings
        for i in converted_matrix:
            # consider first element
            if converted_matrix[i][0] == 1:
                converted_matrix[i][0] = "0"
            # convert to nodes
            for j in range(len(converted_matrix[i])):
                if converted_matrix[i][j] == 1:
                    converted_matrix[i][j] = j
            # filter all 0 out
            converted_matrix[i] = list(filter(lambda a: a != 0, converted_matrix[i]))

            # convert to strings
            converted_matrix[i] = [str(x) for x in converted_matrix[i]]
        return converted_matrix

    def convert_dictionary_to_incidence_matrix(self, dictionary):
        matrix = []
        # initializing matrix with 0
        for i in range(len(dictionary)):
            matrix.append([])
        for i in range(len(matrix)):
            for j in range(len(dictionary)):
                matrix[i].append(0)
        for i in dictionary:
            for j in dictionary[str(i)]:
                matrix[int(i)][int(j)] = 1
        return matrix