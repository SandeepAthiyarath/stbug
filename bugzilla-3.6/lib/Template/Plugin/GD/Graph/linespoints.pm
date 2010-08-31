package Template::Plugin::GD::Graph::linespoints;

use strict;
use warnings;
use base qw( GD::Graph::linespoints Template::Plugin );

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

Template::Plugin::GD::Graph::linespoints - Create line/point graphs with axes and legends

=head1 SYNOPSIS

    [% USE g = GD.Graph.linespoints(x_size, y_size); %]

=head1 EXAMPLES

    [% FILTER null;
        data = [
            ["1st","2nd","3rd","4th","5th","6th","7th", "8th", "9th"],
            [50,  52,  53,  54,  55,  56,  57,  58,  59],
            [60,  61,  61,  63,  68,  66,  65,  61, 58],
            [70,  72,  71,  74,  78,  73,  75,  71, 68],   
        ];  
        
        USE my_graph = GD.Graph.linespoints;
        
        my_graph.set(
            x_label => 'X Label',
            y_label => 'Y label',
            title => 'A Lines and Points Graph',
            y_max_value => 80,
            y_tick_number => 6, 
            y_label_skip => 2,
            y_long_ticks => 1,  
            x_tick_length => 2,  
            markers => [ 1, 5 ],
            skip_undef => 1,
            transparent => 0,
        );  
        my_graph.set_legend('data set 1', 'data set 2', 'data set 3');
        my_graph.plot(data).png | stdout(1);
       END;
    -%]

=head1 DESCRIPTION

The GD.Graph.linespoints plugin provides an interface to the
GD::Graph::linespoints class defined by the GD::Graph module. It allows
one or more (x,y) data sets to be plotted as y versus x lines, plus
symbols placed at each point, in addition to axes and legends.

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

L<Template::Plugin::GD>, L<Template::Plugin::GD::Graph::lines>, L<Template::Plugin::GD::Graph::lines3d>, L<Template::Plugin::GD::Graph::bars>, L<Template::Plugin::GD::Graph::bars3d>, L<Template::Plugin::GD::Graph::points>, L<Template::Plugin::GD::Graph::area>, L<Template::Plugin::GD::Graph::mixed>, L<Template::Plugin::GD::Graph::pie>, L<Template::Plugin::GD::Graph::pie3d>, L<GD>

=cut

# Local Variables:
# mode: perl
# perl-indent-level: 4
# indent-tabs-mode: nil
# End:
#
# vim: expandtab shiftwidth=4:
