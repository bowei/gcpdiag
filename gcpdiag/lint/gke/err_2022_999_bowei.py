# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""bowei's development linter

This is to test how to do development.
"""

import logging

from kubernetes import client, config, watch

from gcpdiag import lint, models
from gcpdiag.queries import gke


def make_config_dict(ca: str, endpoint: str) -> dict:
  """Returns a config dict for creating an authenticated API client.

  Args:
    ca: cluster CA cert associated with the cluster.
    endpoint: IP address endpoint for the API server.
  """
  ret: dict = {}
  ret['apiVersion'] = 'v1'
  ret['clusters'] = [{
      'cluster': {
          'certificate-authority-data': ca,
          'server': 'https://' + endpoint,
      },
      'name': 'c1',
  }]
  ret['contexts'] = [{
      'context': {
          'cluster': 'c1',
          'user': 'u1',
      },
      'name': 'ctx1',
  }]
  ret['users'] = [{
      'name': 'u1',
      'user': {
          'exec': {
              'apiVersion': 'client.authentication.k8s.io/v1beta1',
              'command': 'gke-gcloud-auth-plugin',
              'installHint': 'x',
              'provideClusterInfo': True,
          },
      },
  }]
  return ret


def run_rule(context: models.Context, report: lint.LintReportRuleInterface):
  clusters = gke.get_clusters(context)
  #if not clusters:
  #  logging.info('no clusters found')
  #  report.add_skipped(None, 'no clusters found')
  #  return
  for _, c in sorted(clusters.items()):
    #logging.info('hash %s', c.cluster_hash)
    #logging.info('name %s', c.name)
    #logging.info('location %s', c.location)
    #logging.info('endpoint %s', c.endpoint)
    #logging.info('cluster_ca_certificate %s', c.cluster_ca_certificate)

    # if c.endpoint is None:

    v1 = client.CoreV1Api(api_client=config.new_client_from_config_dict(
        make_config_dict(c.cluster_ca_certificate, c.endpoint), context='ctx1'))

    logging.info("Listing pods with their IPs: %s %s", c.name, c.endpoint)
    ret = v1.list_pod_for_all_namespaces(watch=False)
    for i in ret.items:
      logging.info("%s\t%s\t%s", i.status.pod_ip, i.metadata.namespace,
                   i.metadata.name)
    report.add_ok(c)


# Issues: need to have gcloud in the container with the auth method to run kubectl
