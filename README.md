DokuDrupal
==========

ATTRUBUTIONS/LICENSE
--------------------

license        GPL2            <http://www.gnu.org/licenses/gpl-2.0.html>
author         Alex Shepherd   n00bATNOSPAMn00bsys0p.co.uk

Based on the Dokuwiki MySQL authentication backend by:
Andreas Gohr    andi@splitbrain.org
Chris Smith     chris@jalakai.co.uk
Matthias Grimm  matthias.grimmm@sourceforge.net

INSTALLATION INSTRUCTIONS
-------------------------

To use this authentication backend, a few additions
must be made to your local settings file:

$conf['DrupalRoot']             The relative path of your Drupal instance,
                                ending in a /, such as '../drupal/'

$conf['SQLFindPWHash']          The SQL query to find a password
                                hash for a given user.

$conf['SQLValidateUser']        The SQL query to find a given user
                                by name.

$conf['SQLFindSession']         The query to find a session by its SID

$conf['SQLFindRoles']           The SQL query to list all roles for a
                                given UID

UPDATES/BUGS/FEATURES
---------------------

For updates, to report bugs, or to suggest features, please visit
<http://n00bsys0p.co.uk>, and use the Contact Form, or the email address
given above
