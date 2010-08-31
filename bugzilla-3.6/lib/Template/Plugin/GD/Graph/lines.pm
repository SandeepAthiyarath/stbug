package Template::Plugin::GD::Graph::lines;

use strict;
use warnings;
use base qw( GD::Graph::lines Template::Plugin );

our $VERSION = sprintf("%d.%02d", q$Revision: 1.58 $ =~ /(\d+)\.(\d+)/);

sub new {
    my $class   = shift;
    my $context = shift;
    return $class->SUPER::new(@_);
}

sub set {
    my $self = shift;
    push(@_, %{pop(@_)}) if ( @_ & 1 && ref($_[@_-1]) eq "HASH" );
    $self->SUPER::set(@_);
}


sub set_legend {
    my $self = shift;
    $self->SUPER::set_legend(ref $_[0] ? @{$_[0]} : @_);
}

1;

__END__


=head1 NAME

Template::Plugin::GD::Graph::lines - Create line graphs with axes and legends

=head1 SYNOPSIS

    [% USE g = GD.Graph.lines(x_size, y_size); %]

=head1 EXAMPLES

    [% FILTER null;
        USE g = GD.Graph.lines(300,200);
        x = [1, 2, 3, 4];
        y = [5, 4, 2, 3];
        g.set(
                x_label => 'X Label',
                y_label => 'Y label',
                title => 'Title'
        );
        g.plot([x, y]).png | stdout(1);
       END;
    -%]

    [% FILTER null;
        data = [
            ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                                         "Sep", "Oct", "Nov", "Dec", ],
            [-5, -4, -3, -3, -1,  0,  2,  1,  3,  4,  6,  7],
            [4,   3,  5,  6,  3,1.5, -1, -3, -4, -6, -7, -8],
            [1,   2,  2,  3,  4,  3,  1, -1,  0,  2,  3,  2],
        ];
        
        USE my_graph = GD.Graph.lines();

        my_graph.set(
                x_label => 'Month',
                y_label => 'Measure of success',
                title => 'A Simple Line Graph',

                y_max_value => 8,
                y_min_value => -8,
                y_tick_number => 16,
                y_label_skip => 2,
                box_axis => 0,
                line_width => 3,
                zero_axis_only => 1,
                x_label_position => 1,
                y_label_position => 1,

                x_label_skip => 3,
                x_tick_offset => 2,

                transparent => 0,
        );
        my_graph.set_legend("Us", "Them", "Others");
        my_graph.plot(data).png | stdout(1);
       END;
    -%]

=head1 DESCRIPTION

The GD.Graph.lines plugin provides an interface to the GD::Graph::lines
class defined by the GD::Graph module. It allows one or more (x,y) data
sets to be plotted as y versus x lines with axes and legends.

See L<GD::Graph> for more details.

=head1 AUTHOR

Thomas Boutell wrote the GD graphics library.

Lincoln D. Stein wrote the Perl GD modules that interface to it.

Martien Verbruggen wrote the GD::Graph module.

Craig Barratt E<lt>craig@arraycomm.comE<gt> wrote the original GD
plugins for the Template Toolkit (2001).

Andy Wardley E<lt>abw@cpan.orgE<gt> extracted them from the TT core
into a separate distribution for TT version 2.15.

=head1 COPYRIGHT

Copyright (C) 2001 Craig Barratt E<lt>craig@arraycomm.comE<gt>, 
2006 Andy Wardley E<lt>abw@cpan.orgE<gt>.

GD::Graph is copyright 1999 Martien Verbruggen.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<Template::Plugin::GD>, L<Template::Plugin::GD::Graph::lines3d>, L<Template::Plugin::GD::Graph::bars>, L<Template::Plugin::GD::Graph::bars3d>, L<Template::Plugin::GD::Graph::points>, L<Template::Plugin::GD::Graph::linespoints>, L<Template::Plugin::GD::Graph::area>, L<Template::Plugin::GD::Graph::mixed>, L<Template::Plugin::GD::Graph::pie>, L<Template::Plugin::GD::Graph::pie3d>, L<GD>

=cut

# Local Variables:
# mode: perl
# perl-indent-level: 4
# indent-tabs-mode: nil
# End:
#
# vim: expandtab shiftwidth=4:
