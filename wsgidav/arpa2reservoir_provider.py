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
import copy
import uuid
import urllib

from arpa2 import reservoir


#
# Relations to the project context
#

from wsgidav import compat, util
from wsgidav.dav_error import DAVError, HTTP_FORBIDDEN
from wsgidav.dav_provider import DAVCollection, DAVNonCollection, DAVProvider


#
# Regular Expressions
#

uuid_re = re.compile ('^(?P<uuid>[0-9a-f]{8,8}-[0-9a-f]{4,4}-[0-9a-f]{4,4}-[0-9a-f]{4,4}--[0-9a-f]{12,12})$')


#
# WebDAV Resources
#

class ReservoirResource (DAVNonCollection):
	"""ReservoirResource is a wsgidav interface wrapping
	   arpa2.reservoir.Resource.
	"""

	def __init__ (self, wrap_resource, path, environ):
		DAVNonCollection.__init__ (self, path, environ)
		self.resource = wrap_resource
		self.resfile = None

	def begin_write (self, content_type=None):
		if self.provider.readonly:
			raise DAVError (HTTP_FORBIDDEN)
		if self.resfile is not None:
			self.resfile.close ()
		if content_type is not None:
			self.resource ['mediaType'] = [content_type]
		isbin = content_type [:5] != 'text/'
		self.resfile = self.resource.open (writing=True, reading=False, binary=isbin, truncate=True)
		return self.resfile

	def copy_move_single (self, dest_path, is_move):
		if self.provider.readonly:
			raise DAVError (HTTP_FORBIDDEN)
		#   --> Not implemented yet
		raise DAVError (HTTP_FORBIDDEN)

	# def create_collection (self, name)
	# def create_empty_resource (self, name)
	#   --> Default implementation is fine

	def delete (self):
		if self.provider.readonly:
			raise DAVError (HTTP_FORBIDDEN)
		#   --> Not implemented yet
		raise DAVError (HTTP_FORBIDDEN)

	def end_write (self, with_errors):
		self.resfile.close ()
		self.resfile = None
		self.resource.commit ()

	# def finalize_headers (self, environ, response_headers)
	#   --> No intention of doing anything

	def get_content (self):
		if self.resfile is not None:
			self.resfile.close ()
		isbin = self.resource ['mediaType'] [0] [:5] != 'text/'
		self.resfile = self.resource.open (writing=False, reading=True, binary=isbin)
		return self.resfile

	def get_content_length (self):
		size = 0
		for hash in self ['documentHash']:
			if hash [:6] == '_size ':
				size = int (hash [6:])
		return size

	def get_content_type (self):
		return self.resource ['mediaType'] [0]

	# def get_creation_date (self)
	#   --> Not implemented yet

	def get_descendants (self, collections=True, resources=True, depth_first=False, depth='infinity', add_self=False):
		#TODO#TEST#
		return [ self ]
		#TODO#TEST#

	# def get_directory_info (self)
	# Used in dir_browser/_dir_browser.py ; looks at href, ofe_prefix,
	#	a_class, tr_class, display_name, is_collection, content_length,
	#	display_type, display_type_comment.
	#   --> Default kept as is

	def get_display_info (self):
		# Used in dir_browser/_dir_browser.py ; looks at type, typeComment
		return { 'type': 'Resource', 'typeComment': 'media %s' % self.resource ['mediaType'] [0] }

	def get_display_name (self):
		if 'cn' in self.resource:
			return self.resource ['cn'] [0]
		else:
			return self.resource ['uniqueIdentifier'] [0]

	def get_etag (self):
		for hash in self ['documentHash']:
			if hash [:7] == 'sha256 ':
				return hash [7:]
		return None

	def get_href (self):
		#TODO# Is there a prefix path?  Is this the mount_path?
		return '/%s/%s' % (self.resource.get_colluuid (), self.resource.get_resuuid ())

	def get_last_modified (self):
		# Not implemented, this is the suggested bail-out response
		return None

	# def get_member_list (self)
	# def get_member_names (self)
	#   --> Meaningless for a Resource

	def get_preferred_path (self):
		return '/%s/%s' % (self.resource.get_colluuid (), self.resource.get_resuuid ())

	# def get_properties (self, mode, name_list=None)
	# def get_property_names (self, is_allprop)
	# def get_property_value (self, name)
	#   --> Used the default implementation

	def get_ref_url (self):
		return '/%s/%s' % (self.resource.get_colluuid (), self.resource.get_resuuid ())

	# def handle_copy (self, dest_path, depth_infinity)
	# def handle_delete (self)
	# def handle_move (self, dest_path)
	#   --> Used the default implementation
	#   --> May be more efficiently done directly on LDAP

	# def is_locked (self)
	#   --> Assumed the default implementation will work

	# def move_recursive (self, dest_path)
	#   --> Not implemented here
	#   --> Meaningless for a Resource
	#   --> May be more efficiently done directly on LDAP

	# def prevent_locking (self)
	# def remove_all_locks (self, recursive)
	# def remove_all_properties (self, recursive)
	#   --> Assumed the default implementation will work

	def resolve (self, script_name, path_info):
		return None

	# def set_last_modified (self, dest_path, time_stamp, dry_run)
	# def set_property_value (self, name, value, dry_run)
	#   --> Not implemented here

	def support_content_length (self):
		return True

	def support_etag (self):
		return 'documentHash' in self.resource.keys ()

	def support_modified (self):
		return False

	def support_ranges (self):
		#TODO# Perhaps test if seekable()
		return False

	def support_recursive_delete (self):
		return False

	def support_recursive_move (self):
		return False


#
# WebDAV Resource Collections
#


class ReservoirIndex (DAVCollection):
	"""ReservoirIndex is a wsgidav interface wrapping arpa2.reservoir.Index
	   where the wsgidav objects do not move like a cursor, but point to a
	   fixed location.
	"""

	def __init__ (self, wrap_index, path, environ):
		DAVCollection.__init__ (self, path, environ)
		self.index  = wrap_index

	# def begin_write (self, mediatype):
	#   -> Not sure what it means to a Collection...

	def copy_move_single (self, dest_path, is_move):
		if self.provider.readonly:
			raise DAVError (HTTP_FORBIDDEN)
		#   --> Not implemented yet
		raise DAVError (HTTP_FORBIDDEN)

	def create_collection (self, collname):
		assert not uuid_re.match (collname), 'Collection names must not look like UUIDs'
		clx = copy.copy (self.index)
		reservoir.add_collection (clx, collname)
		return ReservoirIndex (clx, self.path, self.environ)

	def create_empty_resource (self, name):
		assert not uuid_re.match (name), 'Resource names must not look like UUIDs'
		res = reservoir.add_resource (self.index,
				objectClass=['reservoirResource'],
				mediaType=['application/octet-stream'],  # Lack of info :'-(
				uniqueIdentifier=[name])
		return ReservoirResource (res, self.path, self.environ)

	def delete (self):
		if self.provider.readonly:
			raise DAVError (HTTP_FORBIDDEN)
		#   --> Not implemented yet
		raise DAVError (HTTP_FORBIDDEN)

	# def end_write (self)
	#   -> Not sure what it means to a Collection...

	# def finalize_headers (self, environ, ...)
	#   -> No need to customise headers (except? Vary: User --> use arpa2.wsgi.byoid)

	# def get_content (self)
	# def get_content_length (self)
	# def get_content_type (self)
	#   -> Not sure what it means to a Collection...

	# def get_creation_date (self)
	#   -> Not implemented yet

	def get_descendants (self, collections=True, resources=True, depth_first=False, depth='infinity', add_self=False):
		#TODO#TEST#
		return [ self ]
		#TODO#TEST#
		#TODO# depth... '0' | '1' | 'infinity'
		if collections:
			subclx = [ copy.copy (self.index).set_colluuid (uuid) for uuid in self.index.list_index () ]
		else:
			subclx = [ ]
		if resources:
			subres = self.index.load_all_resources ()
		else:
			subres = [ ]
		if add_self:
			me = [ self.index ]
		else:
			me = [ ]
		if depth_first:
			# containers before content
			return me + subclx + subres
		else:
			# content before containers
			return subres + subclx + me

	# def get_directory_info (self)
	# Used in dir_browser/_dir_browser.py ; looks at href, ofe_prefix,
	#	a_class, tr_class, display_name, is_collection, content_length,
	#	display_type, display_type_comment.
	#   -> Not sure what to do here

	def get_display_info (self):
		# Used in dir_browser/_dir_browser.py ; looks at type, typeComment
		return { 'type': 'Resource Collection' }

	# def get_etag (self)
	#   -> Not really useful for a Collection

	def get_href (self):
		#TODO# Is there a prefix path?  Is this the mount_path?
		return '/%s/' % (self.index.get_colluuid(),)

	def get_last_modified (self):
		# Not supported:
		return None

	def get_member (self, name):
		if uuid_re.match (name):
			res = self.index.load_resource (name)
			return ReservoirResource (res, self.path, self.environ)
		else:
			flt = '(uniqueIdentifier=%s)' % urllib.parse.quote (name)
			fnd = reservoir.search_resources (self.index, flt)
			if len (fnd) == 0:
				return None
			elif len (fnd) > 0:
				raise Exception ('Multiple Resources by that name (dataset consistency error)')
			else:
				for res in fnd.values ():
					return ReservoirResource (res, self.path, self.environ)

	def get_member_list (self):
		return self.index.load_all_resources ()

	def get_member_names (self):
		return [ res ['uniqueIdentifier'] for res in self.get_member_list () ]

	def get_preferred_path (self):
		return '/%s/' % self.index.get_colluuid ()

	# def get_properties (self, mode, name_list=None):
	# def get_property_names (self, is_allprop):
	# def get_property_value (self, name)
	#   --> not overridden

	def get_ref_url (self):
		return '/%s/' % self.index.get_colluuid ()

	# def handle_copy (self, dest_path, depth_infinity)
	# def handle_delete (self)
	# def handle_move (self)
	# def is_locked (self)
	# def move_recursive (self, dest_path)
	# def prevent_locking (self)
	# def remove_all_locks (self)
	# def remove_all_properties (self, recursive)
	#   --> not overridden
	#   --> move/copy/del may be more efficiently done directly on LDAP

	def resolve (self, script_name, path_info):
		assert path_info [:1] in ('/',''), 'Invalid path'
		path_info = path_info [1:].split ('/')
		if path_info [-1:] == ['']:
			path_info = path_info [:-1]
		here = copy.copy (self.index)
		domain = self.index.get_domain ()
		(uri,clx,res) = reservoir.uri_canonical (
					domain, cursor=here,
					path=path_info, domain_relative=True)
		self.script = '%s/%s%s' % (self.provider.homedir,domain,uri)
		if res is not None:
			return ReservoirResource (res, self.path, self.environ)
		else:
			return ReservoirIndex    (clx, self.path, self.environ)

	# def set_last_modified (self, dest_path, time_stamp, dry_run)
	# def set_property_value (self, name, value, dry_run)
	#   -> not overridden

	def support_content_length (self):
		return False

	def support_etag (self):
		return False

	def support_modified (self):
		return False

	def support_ranges (self):
		return False

	def support_recursive_delete (self):
		return False

	def support_recursive_move (self, dest_path):
		return False


def _host2domain (homedir, host):
	"""Given a host name, go up in DNS until hitting something
	   that is listed in the arpa2reservoir homedir.
	   
	   TODO: This is a poor solution, explicit mapping is best.
	    - Virtual hosts may not be named under the domain
	    - Subdomains may not be locally known / detected
	"""
	#TODO#TEST#
	return 'arpa2.org'
	#TODO#TEST#
	while True:
		if os.path.exists ('%s/%s' % (homedir,host)):
			return host
		# Raise an exception if no levels are left
		dot = host.index ('.')
		host = host [dot+1:]


class ReservoirHomeIndex (ReservoirIndex):
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

	def __init__ (self, homedir, path, environ):
		host = environ ['HTTP_HOST'].split (':') [0]
		self.domain  = _host2domain (homedir, host)
		self.user = None
		#TODO# Consider using arpa2.wsgi.byoid instead
		if 'LOCAL_USER' not in environ and 'HTTP_USER' in environ:
			environ ['LOCAL_USER'] = urllib.unquote (
					environ ['HTTP_USER'])
		if 'LOCAL_USER' in environ:
			self.user = environ ['LOCAL_USER']
		elif path [:2] == '/~' and len (path) >= 3:
			slash = path.find ('/', 2)
			if slash > -1:
				self.user = path [2:slash-1]
				path = path [slash:]
			else:
				self.user = path [2:]
				path = ''
			#TODO# How to make this path widely used?
			raise Exception ('You should not access /~username without arpa2.wsgi.byoid')
		if self.user is None:
			idx = reservoir.get_domain_user (self.domain, self.user)
		else:
			idx = reservoir.get_domain      (self.domain           )
		ReservoirIndex.__init__ (self, idx, path, environ)
		idx.set_apphint (self.provider.apphint)
		idx.use_apphint ()

	def resolve_TODO_INHERITED (self, script, path):
		(uri,clx,res) = reservoir.uri_canonical (
					self.domain, self.user, self.provider.apphint,
					path, domain_relative=True)
		self.script = '%s/%s%s' % (self.provider.homedir,self.domain,uri)
		if res is not None:
			return ReservoirResource (res, self.path, self.environ)
		else:
			return ReservoirIndex    (clx, self.path, self.environ)


#
# WebDAV Provider for ARPA2 Reservoir
#  - homedir:  directory holding %{REALM}s/%{COLLECTION}s/%{RESOURCE}s
#  - ldapuri:  LDAP URI to connect to (TODO: no authentication yet)
#  - apphint:  Application-suggested entry from the Home Index
#  - readonly: whether changes are permitted
#

class ARPA2ReservoirProvider(DAVProvider):

	def __init__ (self, ldapuri, homedir, apphint, readonly):
		DAVProvider.__init__ (self)
		self.ldapuri  = ldapuri      # Required argument
		self.homedir  = homedir      # Default "/var/arpa2/reservoir"
		self.apphint  = apphint      # Default None
		self.readonly = readonly     # Default False

	# def custom_request_handler (self, environ, ...)
	#   --> not the present intention

	# def exists (self, path, environ)
	#   --> handled in parent
	#   --> we have no efficient implementation
	#   --> will only be used as a last choice

	def get_resource_inst (self, path, environ):
		prefix = ReservoirHomeIndex (self.homedir, '/', environ)
		# Resolve path and return whatever it finds
		return prefix.resolve (self.homedir, path)

	# def is_collection (self, path, environ)
	#   --> handled in parent
	#   --> we have no efficient implementation
	#   --> will only be used as a last choice

	def is_readonly (self):
		return self.readonly

	# def ref_url_to_path (self, ref_url)
	#   --> handled in parent

	# def set_lock_manager (self, lock_manager)
	#   --> handled in parent

	# def set_mount_path (self, mount_path)
	#   --> handled in parent

	# def set_prop_manager (self, prop_manager)
	#   --> handled in parent

	# def set_share_path (self, share_path)
	#   --> handled in parent

