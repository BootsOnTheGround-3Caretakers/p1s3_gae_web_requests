from __future__ import absolute_import
from __future__ import unicode_literals

import datetime
import json
import logging
import os
import sys
import time

from six import integer_types
from six import text_type as unicode

if len(integer_types) == 1:
    long = integer_types[0]
import flask
from google.cloud import ndb
import stripe

import memorystore
from webapp_class_wrapper import wrap_webapp_class

sys.path.insert(0, 'includes')

from datavalidation import DataValidation
from GCP_return_codes import FunctionReturnCodes as RC
from error_handling import CR as RDK
from GCP_datastore_logging import LoggingFuctions
from p1_global_settings import GlobalSettings as GSB
from p1_services import Services as Services
from p1_services import TaskArguments
from p1_services import  TaskNames
from p1_datastores import Datastores as DsP1
from datastore_functions import DatastoreFunctions as DSF
from task_queue_functions import CreateTransactionFunctions as CTF


ndb_client = ndb.Client()


def ndb_wsgi_middleware(wsgi_app):
    def middleware(environ, start_response):
        with ndb_client.context():
            return wsgi_app(environ, start_response)

    return middleware


app = flask.Flask(__name__)
app.wsgi_app = ndb_wsgi_middleware(app.wsgi_app)


class CommonPostHandler(DataValidation):
    def options(self):
        self.response.headers[str('Access-Control-Allow-Headers')] = str(
            'Cache-Control, Pragma, Origin, Authorization, Content-Type, X-Requested-With')
        self.response.headers[str('Access-Control-Allow-Methods')] = str('POST')

    def post(self, *args, **kwargs):
        debug_data = []
        task_id = 'create-transaction:CommonPostHandler:post'

        self.response.headers[str('Access-Control-Allow-Headers')] = str(
            'Cache-Control, Pragma, Origin, Authorization, Content-Type, X-Requested-With')
        self.response.headers[str('Access-Control-Allow-Methods')] = str('POST')

        call_result = self.process_request(*args, **kwargs)
        debug_data.append(call_result)
        if call_result['success'] != RC.success:
            params = {}
            for key in self.request.arguments():
                params[key] = self.request.get(key, None)
            LF = LoggingFuctions()
            LF.logError(call_result[RDK.success],task_id,params,None,None,
                        call_result[RDK.return_msg],call_result)

        self.create_response(call_result)

    def create_response(self, call_result):
        if call_result['success'] == RC.success:
            self.create_success_response(call_result)
        else:
            self.create_error_response(call_result)

    def create_success_response(self, call_result):
        self.response.set_status(204)

    def create_error_response(self, call_result):
        if call_result['success'] == RC.failed_retry:
            self.response.set_status(500)
        elif call_result['success'] == RC.input_validation_failed:
            self.response.set_status(400)
        elif call_result['success'] == RC.ACL_check_failed:
            self.response.set_status(401)

        self.response.out.write(call_result['return_msg'])


@app.route(Services.web_request.create_user.url, methods=["OPTIONS", "POST"])
@wrap_webapp_class(Services.web_request.create_user)
class CreateUser(CommonPostHandler):
    def process_request(self):
        task_id = 'P3-CreateUser:process_request'
        debug_data = []
        return_msg = "P3-CreateUser:process_request "
        user_uid = "1"

        # input validation
        first_name = unicode(self.request.get(TaskArguments.s3t3_first_name, None))
        last_name = unicode(self.request.get(TaskArguments.s3t3_last_name, None))
        phone = unicode(self.request.get(TaskArguments.s3t3_phone_number, None))

        call_result = self.ruleCheck([[first_name,GSB.post_data_rules.required_name],
                                     [last_name,GSB.post_data_rules.required_name],
                                     [phone,DsP1.users._rule_phone_1]])

        debug_data.append(call_result)
        if call_result['success'] != RC.success:
            return_msg += "input validation failed"
            return {'success': RC.input_validation_failed, 'return_msg': return_msg, 'debug_data': debug_data}
        # </end> input validation

        ## create transaction to create user in datastore
        task_sequence = [ {
            'name': TaskNames.s1t4,
            'PMA': {
                TaskArguments.s1t4_first_name: unicode(first_name),
                TaskArguments.s1t4_last_name: unicode(last_name),
                TaskArguments.s1t4_phone_number: unicode(phone)
            }
        }]

        try:
            task_sequence = unicode(json.JSONEncoder().encode(task_sequence))
        except Exception as e:
            return_msg += "JSON encoding of task_queue failed with exception:%s" % e
            return {'success': False, 'return_msg': return_msg, 'debug_data': debug_data}

        task_functions = CTF()
        call_result = task_functions.createTransaction(GSB.project_id, user_uid, task_id,
                                                       task_sequence)
        debug_data.append(call_result)
        if call_result['success'] != RC.success:
            return_msg += 'failed to add task queue function'
            return {'success': call_result['success'], 'debug_data': debug_data, 'return_msg': return_msg}
        ##</end> create transaction to create user in datastore

        return {'success': RC.success, 'return_msg': return_msg, 'debug_data': debug_data}


if __name__ == "__main__":
    app.run(debug=True)
