# @file:    Boolean.pm
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

# Package Start
package Deploy::Boolean;

use strict;
use base qw(Exporter);

our(@EXPORT, @EXPORT_OK, %EXPORT_TAGS);

use constant {TRUE => 1, FALSE => 0, SUCCESS => 0, FAILURE => 1};
use constant {true => 1, false => 0, success => 0, failure => 1};

@EXPORT = qw(TRUE FALSE SUCCESS FAILURE true false success failure);

%EXPORT_TAGS = (
    Boolean => [@EXPORT[0..3]],
    boolean => [@EXPORT[4..7]]
);

1;

# vi:set ft=perl ts=4 sw=4 et fdm=marker:
