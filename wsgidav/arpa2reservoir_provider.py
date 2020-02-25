# -*- coding: utf-8 -*-
# (c) 2020 Rick van Rein; see WsgiDAV https://github.com/mar10/wsgidav
# Licensed under the MIT license:
# http://www.opensource.org/licenses/mit-license.php
"""
Implementation of a DAV provider that serves from ARPA2 Reservoir.

Specifically, the implementation uses a file system for objects with
directory hierarchy %{REALM}s/%{COLLECTION}s/%{RESOURCE}s where:

  - %{REALM}s      is a domain in lowercase, no trailing dot, punycode
  - %{COLLECTION}s is a UUID   in lowercase, with the usual dashes
  - %{RESOURCE}s   is a UUID   in lowercase, with the usual dashes

Metadata for this structure is stored in LDAP, using the structure

  resource=%{RESOURCE}s,resins=%{COLLECTION}s,associatedDomain=%{REALM}s,
	ou=Reservoir,o=arpa2.net,ou=InternetWide

The right/top 3 levels ou/o/ou define the ARPA2 Reservoir application
and are meant to be used by all instantiations.  Specifically o=arpa2.net
references the _defining_ domain, not necessarily the _hosting_ domain.

Collections are an Index, meaning that they can define names to follow
to find the next Collection in a (virtual) path; domains and their users
also have an Index, namely at the associatedDomain=%{REALM}s,... level
and at a branch uid=%{USER}s,associatedDomain=%{REALM}s,...; user names
may be provided through a %{USER}s@ before the host name in the URI or
perhaps through a URI path that starts with /~%{USER}s/ instead.  The
code below assumes draft-vanrein-http-unauth-user-05, which sets an
environment variable LOCAL_USER=%{USER} -- a server may however provide
only HTTP_USER=escape(%{USER}) as an automated form.

More information on http://reservoir.arpa2.net

:class:`~wsgidav.arpa2reservoir_provider.ARPA2ReservoirProvider`
implements a DAV resource provider that publishes the file system.

If ``readonly=True`` is passed, write attempts will raise HTTP_FORBIDDEN.

This provider creates instances of
:class:`~wsgidav.arpa2reservoir_provider.Resource`
to represent individual resources
:class:`~wsgidav.arpa2reservoir_provider.ResourceIndex`
to represent indexes (such as directories, domains or users) respectively.
"""


import os

import re

uuid_patn = 

uuid_re = re.compile ('^(?P<uuid>[0-9a-f]{8,8}-[0-9a-f]{4,4}-[0-9a-f]{4,4}-[0-9a-f]{4,4}--[0-9a-f]{12,12})$')
uuid_name_re = re.compile ('^(?P<uuid>[0-9a-f]{8,8}-[0-9a-f]{4,4}-[0-9a-f]{4,4}-[0-9a-f]{4,4}--[0-9a-f]{12,12}) (?P<name>.+)$')
uuid_name_re = re.compile ('^(?P<uuid>[0-9a-f]{8,8}-[0-9a-f]{4,4}-[0-9a-f]{4,4}-[0-9a-f]{4,4}--[0-9a-f]{12,12})( (?P<name>.+))?$')


import uuid

reservoir_uuid = '904dfdb5-6b34-3818-b580-b9a0b4f7e7a9'

def random_uuid ():
	return str (uuid.uuid4 ()).lower ()


import urllib


import ldap
from ldap import MOD_ADD, MOD_DELETE, MOD_REPLACE, MOD_INCREMENT
from ldap import SCOPE_BASE, SCOPE_ONELEVEL, SCOPE_SUBTREE
from ldap import NO_SUCH_OBJECT, ALREADY_EXISTS, NOT_ALLOWED_ON_NONLEAF

basedn = 'ou=Reservoir,o=arpa2.net,ou=InternetWide'



#
# Relations to the project context
#

from wsgidav import compat, util
from wsgidav.dav_error import DAVError, HTTP_FORBIDDEN
from wsgidav.dav_provider import DAVCollection, DAVNonCollection, DAVProvider


#
# WebDAV Resources
#

class ReservoirResource (DAVNonCollection):

	def __init__ (self, path, environ):
		DAVNonCollection.__init__ (self, path, environ)

	def get_content_length (self):

	def get_content_type (self):

	def get_content (self):

	def support_ranges (self):

	def begin_write (self, content_type=None):

	def end_write (self, with_errors):

	def resolve (self, script_name, path_info):


#
# WebDAV Resource Collections
#


class ReservoirResourceIndex (DAVCollection):

	def __init__ (self, path, environ, domain, colluuid):
		DAVCollection.__init__ (self, path, environ, domain, colluuid)
		self.domain = domain
		self.colluuid = colluuid

	def colldn (self, colluuid):
		return 'resins=%s,%s' + (colluuid, self.basedn)

	def create_empty_resource (self, name):
		assert not uuid_re.match (name), 'Resource names must not look like UUIDs'
		raise NotImplementedError ('#TODO# Pick a random UUID, create Resource object for it')

	def create_collection (self, collname):
		assert not uuid_re.match (collname), 'Collection names must not look like UUIDs'
		raise NotImplementedError ('#TODO# Pick a random UUID, create a resins object for it')
		raise NotImplementedError ('#TODO# Add a reservoirRef with the new "UUID name"')
		colluuid = random_uuid ()
		dn1 = 'resins=' + colluuid + ',associatedDomain=' + self.environ ['config'] ['HTTP_HOST'] + ',' + base
		at1 = [
			('objectClass', [
				'reservoirCollection',
				'resourceInstance',
				'accessControlledObject',
				'reservoirIndex']),
			('rescls', reservoir_uuid),
			('resins', colluuid),
			('cn', collname),
		]
		dap.add_s (dn1, at1)
		raise NotImplementedError ('#TODO# Insert colluuid ascollname in the index of self')

	def get_member (self, name):
		if name and uuid_re.match (name):
			if isinstance (self, ResourceAppCollection):
				# The domain/user colluuid may be overridden
				member_dn = self.colldn (name)
				member_script = '/' + name
			elif isinstance (self, Resource):
				# Already at the terminal node of a Resource
				# Does not happen!  Not here!
				return None
			else:
				raise NotImplementedError ('#TODO# Lookup the Resource by the given name')
		else:
			raise NotImplementedError ('#TODO# Lookup reservoirRef by name (allowing None)')
		raise NotImplementedError ('#TODO# Check collection ACL at member_dn, return if okay')

	def get_member_names (self):
		raise NotImplementedError ('#TODO# Retrieve names of reservoirRef values')

	#DEFAULT# def support_recursive_delete (self):

	def delete (self):
		"""Delete the current Collection and its Resources.
		   Do not remove references to other Collections, but
		   TODO:SOMEDAY mark them as potentially orphaned.
		"""
		raise NotImplementedError ("#TODO# Delete collection and resources from LDAP and files")

	def copy_move_single (self, dest_path, is_move):
		raise NotImplementedError ('#TODO# Copy or Move a single file')

	#DEFAULT# def support_recursive_move (self, dest_path):

	def resolve (self, script_name, path_info):
		"""Resolve a resource.  Only the first and last elements
		   of the path_info may be a UUID, for collection and
		   resource, respectively.  Just one UUID is considered
		   a collection.  Path elements between first and last
		   are resolved as index names, changing the original
		   collection UUID.
		"""
		elem = path_info.strip ('/').split ('/')
		if len (elem) == 0:
			# No path, return the base object
			return self
		elif uuid_re.match (elem [0]):
			# Initial UUID indicates a Collection
			cursor = 
			elem = elem [1:]
		# Step through all but the outer path elements
		for step in elem [:-2]:
			assert not uuid_re.match (step), 'Unexpected UUID in path'
			cursor = cursor.get_member (step)
		# Retrieve a Resource if the last path element is a UUID
		if len (elem) < 2:
			pass
		elif uuid_re.match (elem [-1]):
			# Lookup the last element as a UUID
			cursor = cursor.ReservoirResource (
				cursor.get_preferred_path () + '/' + elem [-1],
				self.environ)
		else:
			# First try as a Collection, else Resource
			try:
				cursor = cursor.get_member (elem [-1])
			except:
				raise NotImplementedError ('#TODO# Lookup resource by name in LDAP')
		return cursor


class ReservoirResourceAppCollection (ResourceIndex):
	"""The wrapper for a Resource Resource App Collection.
	   This finds an initial Resource Index, based on the domain
	   and an optional user.  The app name is looked up from this
	   initial Resource Index to find the home Resource Collection
	   for the current application.  When the app name is not
	   specified or when it is not in the initial Resource Index,
	   the entry without a name is used to find the home Resource
	   Collection.  From there, the resolve() call is used to
	   locate other objects.
	"""

	def __init__ (self, path, environ, domain=None, user=None, app=None):
		ResourceIndex.__init__ (self, path, environ)
		app    = environ ['wsgidav.config'] ['app'   ]
		realms = environ ['wsgidav.config'] ['realms']
		realm  = environ ['HTTP_HOST'].split (':') [0]
		#TODO# %-escape for LDAP DN
		dn = 'ou=Reservoir,o=arpa2.net,ou=InternetWide'
		dn = 'associatedDomain=%s,%s' % (self.domain,dn)
		self.basedn = dn
		if 'LOCAL_USER' not in environ and 'HTTP_USER' in environ:
			environ ['LOCAL_USER'] = urllib.unquote (
					environ ['HTTP_USER'])
		if 'LOCAL_USER' in environ:
			# user = environ ['LOCAL_USER']
			dn = 'uid=%s,%s' % (environ ['LOCAL_USER'], dn)
		elif path [:2] == '/~' and len (path) >= 3:
			slash = path.find ('/', 2)
			if slash > -1:
				# user = path [2:slash-1]
				dn = 'uid=%s,%s' % (path [2:slash-1], dn)
				path = path [slash:]
			else:
				# user = path [2:]
				dn = 'uid=%s,%s' % (path [2:], dn)
				path = ''
		self.dn = dn
		self.home_index = self.get_member (app)
		self.dn = self.home_index.dn
		self.script = realms + '/' + realm

	def resolve (self, path):
		return self.home_index.resolve (
				self.script, path,
				is_prefix=True)


#
# WebDAV Provider for ARPA2 Reservoir
#  - realms:   directory holding %{REALM}s/%{COLLECTION}s/%{RESOURCE}s
#  - ldapuri:  LDAP URI to connect to (TODO: no authentication yet)
#  - readonly: whether changes are permitted
#

class ARPA2ReservoirProvider(DAVProvider):

	def __init__ (self, ldapuri, realms, app, readonly):
		DAVProvider.__init__ (self)
		self.ldapuri  = ldapuri
		self.realms   = realms
		self.app      = app
		self.readonly = readonly

	def is_readonly (self):
		return self.readonly

	def get_resource_inst(self, path, environ):
		prefix = ResourceAppCollection ('/', environ)
		# Resolve path and return whatever it finds
		return prefix.resolve (script, path)

