#!/usr/bin/env python3

#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

import json
import requests
import os
import sys

def main():
  if "GITHUB_TOKEN" not in os.environ:
    print("The GITHUB_TOKEN authentication token is missing!")
    return False

  if "GITHUB_RUN_ID" not in os.environ:
    print("The GITHUB_RUN_ID environment variable is missing!")
    return False

  if "GITHUB_HEAD_REF" not in os.environ:
    print("The GITHUB_HEAD_REF environment variable is missing. Ignoring")
    return True

  auth_token = os.environ["GITHUB_TOKEN"]
  if len(auth_token) == 0:
    print("The GitHub token is empty!")
    return False

  current_workflow_id = os.environ["GITHUB_RUN_ID"]
  if len(current_workflow_id) == 0:
    print("The run id is empty!")
    return False

  current_workflow_id = int(current_workflow_id)

  branch_name = os.environ["GITHUB_HEAD_REF"]
  if len(branch_name) == 0:
    print("Ignoring because this event is not a pull request")
    return True

  # This should never happen, since we already make sure that the
  # GITHUB_HEAD_REF env var is defined
  if branch_name == "master":
    print("Running against the master branch. Skipping")
    return True

  print("Aborting stale workflows running for branch {}".format(branch_name))
  print("Current workflow (#{}) will be ignored".format(current_workflow_id))

  request_helper = RequestHelper("lifting-bits", "anvill", auth_token)

  running_workflow_list = request_helper.get_active_workflow_list(branch_name, "in_progress")
  if running_workflow_list is None:
    print("Failed to list the running workflows")
    return False

  queued_workflow_list = request_helper.get_active_workflow_list(branch_name, "queued")
  if queued_workflow_list is None:
    print("Failed to list the queued workflows")
    return False

  for run_id in queued_workflow_list:
    if run_id == current_workflow_id:
      continue

    if request_helper.abort_workflow(run_id):
      print("Queued workflow {} has been aborted".format(run_id))
    else:
      print("Failed to abort queued workflow {}".format(run_id))

  for run_id in running_workflow_list:
    if run_id == current_workflow_id:
      continue

    if request_helper.abort_workflow(run_id):
      print("Running workflow {} has been aborted".format(run_id))
    else:
      print("Failed to abort running workflow {}".format(run_id))

  return True

class RequestHelper:
  _base_url = "https://api.github.com/repos/"
  _organization = ""
  _repository = ""
  _username = ""
  _token = ""

  def __init__(self, organization, repository, token):
    self._organization = organization
    self._repository = repository
    self._token = token

  def organization(self):
    return self._organization

  def repository(self):
    return self._repository

  def abort_workflow(self, run_id):
    url = self._base_url + self._organization + "/" + self._repository + "/actions/runs/" + str(run_id) + "/cancel"

    response = requests.post(url, auth=("Bearer", self._token))
    if response.status_code != requests.codes.accepted:
      return False

    return True

  def get_active_workflow_list(self, branch_name, status):
    url = self._base_url + self._organization + "/" + self._repository + "/actions/runs"

    # "status" and "conclusion" are different fields in the JSON response
    # but they use the same request parameter when creating a call
    response = requests.get(
      url,

      params={
        "branch": branch_name,
        "status": status,
      },

      auth=("Bearer", self._token)
    )

    if response.status_code != requests.codes.ok:
      return None

    try:
      response = json.loads(response.text)

    except ValueError:
      return None

    workflow_run_list = response.get("workflow_runs")
    if type(workflow_run_list) != list:
      return None

    workflow_list = []

    for workflow_run in workflow_run_list:
      if type(workflow_run) != dict:
        continue

      entry = {}

      run_id = workflow_run.get("id")
      if type(run_id) != int:
        return None

      workflow_list.append(run_id)

    return workflow_list

if __name__ == "__main__":
  exit_code = 0 if main() else 1
  sys.exit(exit_code)
