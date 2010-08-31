#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#
#  Chart::Pie                    #
#                                #
#  written by Chart Group        #
#                                #
#  maintained by the Chart Group #
#  Chart@wettzell.ifag.de        #
#                                #
#                                #
#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<#

package Chart::Pie;

use Chart::Base '2.4.1';
use GD;
use Carp;
use strict;

@Chart::Pie::ISA = qw(Chart::Base);
$Chart::Pie::VERSION = '2.4.1';

#>>>>>>>>>>>>>>>>>>>>>>>>>>#
#  public methods go here  #
#<<<<<<<<<<<<<<<<<<<<<<<<<<#



#>>>>>>>>>>>>>>>>>>>>>>>>>>>#
#  private methods go here  #
#<<<<<<<<<<<<<<<<<<<<<<<<<<<#

#Overwrite the legend methods to get the right legend
sub _draw_right_legend {
  my $self = shift;
  my $data = $self->{'dataref'};
  my @labels = @{$data->[0]};
  my ($x1, $x2, $x3, $y1, $y2, $width, $color, $misccolor, $w, $h, $brush);
  my $font = $self->{'legend_font'};
  my $l1 = 0;
  my $l2 =0;
  my ($i, $j, $label, $dataset_sum);
  my $max_label_len = 1;
  
  # make sure we're using a real font
  unless ((ref ($font)) eq 'GD::Font') {
    croak "The subtitle font you specified isn\'t a GD Font object";
  }

  # get the size of the font
  ($h, $w) = ($font->height, $font->width);

  # get the miscellaneous color
  $misccolor = $self->_color_role_to_index('misc');

  #find out what the sum of all datapoits is, needed for the Labels with percent
    $dataset_sum = 0;
    for my $j (0..$self->{'num_datapoints'}) 
    {
        if(defined $data->[1][$j])
        {
            $dataset_sum += $data->[1][$j];
        }
    }
  
    # find out how who wide the largest label text is
    foreach (@labels) 
    {
        if ( length($_) > $l1) 
        {
            $l1 = length($_);
        }
    }
    for (my $i =0 ; $i < ($self->{'num_datapoints'}) ; $i++) 
    {
        if ( length($data->[1][$i]) > $l2  ) 
        {
            $l2 = length($data->[1][$i]);
        }
    }
  
    if ($self->{'legend_label_values'} =~ /^value$/i ) 
    {
        $max_label_len = $l1 + $l2 +1;
    }
    elsif ($self->{'legend_label_values'} =~ /^percent$/i ) 
    {
        $max_label_len = $l1 +7;
    }
    elsif ($self->{'legend_label_values'} =~ /^both$/i ) 
    {
        $max_label_len = $l1 + $l2 +9;
    }
    else 
    {
        $max_label_len = $l1;
    }

    # find out how wide the largest label is
    $width = (2 * $self->{'text_space'})
    #+ ($self->{'max_legend_label'} * $w)
    + $max_label_len *$w
    + $self->{'legend_example_size'}
    + (2 * $self->{'legend_space'});

    # get some starting x-y values
    $x1 = $self->{'curr_x_max'} - $width;
    $x2 = $self->{'curr_x_max'};
    $y1 = $self->{'curr_y_min'} + $self->{'graph_border'} ;
    $y2 = $self->{'curr_y_min'} + $self->{'graph_border'} + $self->{'text_space'}
          + ($self->{'num_datapoints'} * ($h + $self->{'text_space'}))
	  + (2 * $self->{'legend_space'});

    # box the legend off
    $self->{'gd_obj'}->rectangle ($x1, $y1, $x2, $y2, $misccolor);

    # leave that nice space inside the legend box
    $x1 += $self->{'legend_space'};
    $y1 += $self->{'legend_space'} + $self->{'text_space'};

    # now draw the actual legend
    for (0..$#labels) 
    {
        # get the color
        $color = $self->_color_role_to_index('dataset'.$_);

        # find the x-y coords
        $x2 = $x1;
        $x3 = $x2 + $self->{'legend_example_size'};
        $y2 = $y1 + ($_ * ($self->{'text_space'} + $h)) + $h/2;

        # do the line first
        $self->{'gd_obj'}->line ($x2, $y2, $x3, $y2, $color);

        # reset the brush for points
        $brush = $self->_prepare_brush($color, 'point',
	                    	$self->{'pointStyle' . $_});
        $self->{'gd_obj'}->setBrush($brush);
        # draw the point
        $self->{'gd_obj'}->line(int(($x3+$x2)/2), $y2,
				int(($x3+$x2)/2), $y2, gdBrushed);

        # now the label
        $x2 = $x3 + (2 * $self->{'text_space'});
        $y2 -= $h/2;
        if (defined $data->[1][$_]) 
        {
            if ( $self->{'legend_label_values'} =~ /^value$/i ) 
            {
                $self->{'gd_obj'}->string($font, $x2, $y2, $labels[$_].' '.$data->[1][$_], $color);
            }
            elsif ( $self->{'legend_label_values'} =~ /^percent$/i ) 
            {
                $label = sprintf("%s %4.2f%%",$labels[$_], $data->[1][$_] / ($dataset_sum || 1)* 100);
                $self->{'gd_obj'}->string($font, $x2, $y2, $label, $color);
            }
            elsif ( $self->{'legend_label_values'} =~ /^both$/i ) 
            {
                if ( $data->[1][$_] =~ /\./ ) 
                {
                    $label = sprintf("%s %4.2f%% %.2f",$labels[$_], $data->[1][$_] / ($dataset_sum || 1) * 100, $data->[1][$_]);
                }
                else 
                {
                    $label = sprintf("%s %4.2f%% %d",$labels[$_], $data->[1][$_] / ($dataset_sum || 1)* 100, $data->[1][$_]);
                }
                $self->{'gd_obj'}->string($font, $x2, $y2, $label, $color);
            }
            else 
            {
                $self->{'gd_obj'}->string($font, $x2, $y2, $labels[$_], $color);
            }

        }
    }

    # mark off the used space
    $self->{'curr_x_max'} -= $width;

    # and return
    return 1;
}


## put the legend on the left of the chart
sub _draw_left_legend {
  my $self = shift;
  my $data = $self->{'dataref'};
  my @labels = @{$data->[0]};
  my ($x1, $x2, $x3, $y1, $y2, $width, $color, $misccolor, $w, $h, $brush);
  my $font = $self->{'legend_font'};
  my $max_label_len= 1;;
  my $l1 = 0;
  my $l2 = 0;
  my ($dataset_sum, $label);
  # make sure we're using a real font
  unless ((ref ($font)) eq 'GD::Font') {
    croak "The subtitle font you specified isn\'t a GD Font object";
  }

  # get the size of the font
  ($h, $w) = ($font->height, $font->width);

  # get the miscellaneous color
  $misccolor = $self->_color_role_to_index('misc');

  #find out what the sum of all datapoits is, needed for the Labels with percent
  $dataset_sum = 0;
  for my $j (0..$self->{'num_datapoints'}) {
     if(defined $data->[1][$j]) {
       $dataset_sum += $data->[1][$j];
     }
  }

  # find out how who wide the largest label text is
  foreach (@labels) {
   if ( length($_) > $l1) {
     $l1 = length($_);
   }
  }
  for (my $i =0 ; $i < ($self->{'num_datapoints'}) ; $i++) {
   if ( length($data->[1][$i]) > $l2 ) {
      $l2 = length($data->[1][$i]);
   }
  }

  if ($self->{'legend_label_values'} =~ /^value$/i ) {
    $max_label_len = $l1 + $l2 +1;
  }
  elsif ($self->{'legend_label_values'} =~ /^percent$/i ) {
    $max_label_len = $l1 +7;
  }
  elsif ($self->{'legend_label_values'} =~ /^both$/i ) {
    $max_label_len = $l1 + $l2 +9;
  }
  else {
    $max_label_len = $l1;
  }

  # find out how wide the largest label is
  $width = (2 * $self->{'text_space'})
    + ($max_label_len * $w)
    + $self->{'legend_example_size'}
    + (2 * $self->{'legend_space'});

  # get some base x-y coordinates
  $x1 = $self->{'curr_x_min'};
  $x2 = $self->{'curr_x_min'} + $width;
  $y1 = $self->{'curr_y_min'} + $self->{'graph_border'} ;
  $y2 = $self->{'curr_y_min'} + $self->{'graph_border'} + $self->{'text_space'}
          + ($self->{'num_datapoints'} * ($h + $self->{'text_space'}))
	  + (2 * $self->{'legend_space'});

  # box the legend off
  $self->{'gd_obj'}->rectangle ($x1, $y1, $x2, $y2, $misccolor);

  # leave that nice space inside the legend box
  $x1 += $self->{'legend_space'};
  $y1 += $self->{'legend_space'} + $self->{'text_space'};

  # now draw the actual legend
  for (0..$#labels) {
    # get the color
    $color = $self->_color_role_to_index('dataset'.$_);

    # find the x-y coords
    $x2 = $x1;
    $x3 = $x2 + $self->{'legend_example_size'};
    $y2 = $y1 + ($_ * ($self->{'text_space'} + $h)) + $h/2;

    # do the line first
    $self->{'gd_obj'}->line ($x2, $y2, $x3, $y2, $color);

    # reset the brush for points
    $brush = $self->_prepare_brush($color, 'point',
				$self->{'pointStyle' . $_});
    $self->{'gd_obj'}->setBrush($brush);
    # draw the point
    $self->{'gd_obj'}->line(int(($x3+$x2)/2), $y2,
				int(($x3+$x2)/2), $y2, gdBrushed);

    # now the label
    $x2 = $x3 + (2 * $self->{'text_space'});
    $y2 -= $h/2;
    if ( $self->{'legend_label_values'} =~ /^value$/i ) {
        $self->{'gd_obj'}->string($font, $x2, $y2, $labels[$_].' '.$data->[1][$_], $color);
    }
    elsif ( $self->{'legend_label_values'} =~ /^percent$/i ) {
        $label = sprintf("%s %4.2f%%",$labels[$_], $data->[1][$_] / ($dataset_sum || 1) * 100);
        $self->{'gd_obj'}->string($font, $x2, $y2, $label, $color);
    }
    elsif ( $self->{'legend_label_values'} =~ /^both$/i ) {
        if ($data->[1][$_] =~ /\./) {
           $label = sprintf("%s %4.2f%% %.2f",$labels[$_], $data->[1][$_] / ($dataset_sum || 1) * 100, $data->[1][$_]);
        }
        else {
           $label = sprintf("%s %4.2f%% %d",$labels[$_], $data->[1][$_] / ($dataset_sum || 1)* 100, $data->[1][$_]);
        }
        $self->{'gd_obj'}->string($font, $x2, $y2, $label, $color);
    }
    else {
        $self->{'gd_obj'}->string($font, $x2, $y2, $labels[$_], $color);
    }

  }

  # mark off the used space
  $self->{'curr_x_min'} += $width;

  # and return
  return 1;
}


## put the legend on the bottom of the chart
sub _draw_bottom_legend {
  my $self = shift;
  my $data = $self->{'dataref'};
  my @labels =@{$data->[0]};
  my ($x1, $y1, $x2, $x3, $y2, $empty_width, $max_label_width, $cols, $rows, $color, $brush);
  my ($col_width, $row_height, $r, $c, $index, $x, $y, $w, $h);
  my $font = $self->{'legend_font'};
  my $max_label_len;
  my $l1 = 0;
  my $l2 = 0;
  my ($dataset_sum, $j);
  my $label;
  # make sure we're using a real font
  unless ((ref ($font)) eq 'GD::Font') {
    croak "The subtitle font you specified isn\'t a GD Font object";
  }

  # get the size of the font
  ($h, $w) = ($font->height, $font->width);

  # find the base x values
  $x1 = $self->{'curr_x_min'} + $self->{'graph_border'}  ;
         # + ($self->{'y_tick_label_length'} * $self->{'tick_label_font'}->width)
	 # + $self->{'tick_len'} + (3 * $self->{'text_space'});
  $x2 = $self->{'curr_x_max'} - $self->{'graph_border'};
  if ($self->{'y_label'}) {
    $x1 += $self->{'label_font'}->height + 2 * $self->{'text_space'};
  }
  if ($self->{'y_label2'}) {
    $x2 -= $self->{'label_font'}->height + 2 * $self->{'text_space'};
  }

    #find out what the sum of all datapoits is, needed for the Labels with percent
    $dataset_sum = 0;
    for $j (0..$self->{'num_datapoints'}) 
    {
        if(defined $data->[1][$j])
        {       
            $dataset_sum += $data->[1][$j];
        }
    }

    # find out how who wide the largest label text is, especially look what kind of
    # label is needed
    foreach (@labels) 
    {
        if ( length($_) > $l1) 
        {
            $l1 = length($_);
        }
    }
    for (my $i =0 ; $i < ($self->{'num_datapoints'}) ; $i++) 
    {
        if ( length($data->[1][$i]) > $l2  ) 
        {
            $l2 = length($data->[1][$i]);
        }
    }


    if ($self->{'legend_label_values'} =~ /^value$/i ) 
    {
        $max_label_len = $l1 + $l2 +1;
    }
    elsif ($self->{'legend_label_values'} =~ /^percent$/i ) 
    {
        $max_label_len = $l1 +7;
    }
    elsif ($self->{'legend_label_values'} =~ /^both$/i ) 
    {
        $max_label_len = $l1 + $l2 +9;
    }
    else 
    {
        $max_label_len = $l1;
    }
  
    # figure out how wide the columns need to be, and how many we
    # can fit in the space available
    $empty_width = ($x2 - $x1) - (2 * $self->{'legend_space'});
    $max_label_width = $max_label_len * $w
    #$self->{'max_legend_label'} * $w
    + (4 * $self->{'text_space'}) + $self->{'legend_example_size'};
  $cols = int ($empty_width / $max_label_width);
  unless ($cols) {
    $cols = 1;
  }
  $col_width = $empty_width / $cols;

  # figure out how many rows we need, remember how tall they are
  $rows = int ($self->{'num_datapoints'} / $cols);
  unless (($self->{'num_datapoints'} % $cols) == 0) {
    $rows++;
  }
  unless ($rows) {
    $rows = 1;
  }
  $row_height = $h + $self->{'text_space'};

  # box the legend off
  $y1 = $self->{'curr_y_max'} - $self->{'text_space'}
          - ($rows * $row_height) - (2 * $self->{'legend_space'});
  $y2 = $self->{'curr_y_max'};
  $self->{'gd_obj'}->rectangle($x1, $y1, $x2, $y2,
                               $self->_color_role_to_index('misc'));
  $x1 += $self->{'legend_space'} + $self->{'text_space'};
  $x2 -= $self->{'legend_space'};
  $y1 += $self->{'legend_space'} + $self->{'text_space'};
  $y2 -= $self->{'legend_space'} + $self->{'text_space'};

  # draw in the actual legend
  for $r (0..$rows-1) {
    for $c (0..$cols-1) {
      $index = ($r * $cols) + $c;  # find the index in the label array
      if ($labels[$index]) {
	# get the color
        $color = $self->_color_role_to_index('dataset'.$index);

        # get the x-y coordinate for the start of the example line
	$x = $x1 + ($col_width * $c);
        $y = $y1 + ($row_height * $r) + $h/2;

	# now draw the example line
        $self->{'gd_obj'}->line($x, $y,
                                $x + $self->{'legend_example_size'}, $y,
                                $color);

        # reset the brush for points
        $brush = $self->_prepare_brush($color, 'point',
				$self->{'pointStyle' . $index});
        $self->{'gd_obj'}->setBrush($brush);
        # draw the point
        $x3 = int($x + $self->{'legend_example_size'}/2);
        $self->{'gd_obj'}->line($x3, $y, $x3, $y, gdBrushed);

        # adjust the x-y coordinates for the start of the label
	$x += $self->{'legend_example_size'} + (2 * $self->{'text_space'});
        $y = $y1 + ($row_height * $r);

	# now draw the label
        if ( $self->{'legend_label_values'} =~ /^value$/i ) {
           $self->{'gd_obj'}->string($font, $x, $y, $labels[$index].' '.$data->[1][$index], $color);
	 #$self->{'gd_obj'}->stringTTF($color, FONT, 10, 0, $x, $y+10, $labels[$index].' '.$data->[1][$index]);     ############
        }
        elsif ( $self->{'legend_label_values'} =~ /^percent$/i ) {
           $label = sprintf("%s %4.2f%%",$labels[$index], $data->[1][$index] / ($dataset_sum || 1)* 100);
           $self->{'gd_obj'}->string($font, $x, $y, $label, $color);
        }
        elsif ( $self->{'legend_label_values'} =~ /^both$/i ) {
           if ($data->[1][$index] =~ /\./) {
              $label = sprintf("%s %4.2f%% %.2f",$labels[$index], $data->[1][$index] / ($dataset_sum || 1) * 100, $data->[1][$index]);
           }
           else {
              $label = sprintf("%s %4.2f%% %d",$labels[$index], $data->[1][$index] / ($dataset_sum || 1) * 100, $data->[1][$index]);
           }
            $self->{'gd_obj'}->string($font, $x, $y, $label, $color); ###
	   # $self->{'gd_obj'}->stringTTF($color, FONT, 10, 0, $x, $y, $label);
  
        }
        else {
           $self->{'gd_obj'}->string($font, $x, $y, $labels[$index], $color);
        }
      }
    }
  }

  # mark off the space used
  $self->{'curr_y_max'} -= ($rows * $row_height) + $self->{'text_space'}
			      + (2 * $self->{'legend_space'});

  # now return
  return 1;
}


## put the legend on top of the chart
sub _draw_top_legend {
  my $self = shift;
  my $data = $self->{'dataref'};
  my ($max_label_len);
  my $l1 = 0;
  my $l2 = 0;
  my @labels = @{$data->[0]};
  my ($x1, $y1, $x2, $x3, $y2, $empty_width, $max_label_width, $cols, $rows, $color, $brush);
  my ($col_width, $row_height, $r, $c, $index, $x, $y, $w, $h, $dataset_sum, $label);
  my $font = $self->{'legend_font'};

  # make sure we're using a real font
  unless ((ref ($font)) eq 'GD::Font') {
    croak "The subtitle font you specified isn\'t a GD Font object";
  }

  # get the size of the font
  ($h, $w) = ($font->height, $font->width);

    #find out what the sum of all datapoits is, needed for the Labels with percent
    $dataset_sum = 0;
    for my $j (0..$self->{'num_datapoints'}) 
    {
        if(defined $data->[1][$j])
        {
           $dataset_sum += $data->[1][$j];
        }
    }
     
    # get some base x coordinates
    $x1 = $self->{'curr_x_min'}
          + $self->{'graph_border'};
         # + $self->{'y_tick_label_length'} * $self->{'tick_label_font'}->width
	 # + $self->{'tick_len'} + (3 * $self->{'text_space'});
    $x2 = $self->{'curr_x_max'} - $self->{'graph_border'};
    if ($self->{'y_label'}) 
    {
        $x1 += $self->{'label_font'}->height + 2 * $self->{'text_space'};
    }
    if ($self->{'y_label2'}) 
    {
        $x2 -= $self->{'label_font'}->height + 2 * $self->{'text_space'};
    }

    # find out how who wide the largest label text is
    foreach (@labels) 
    {
        if ( length($_) > $l1) 
        {
            $l1 = length($_);
        }
    }
    for (my $i =0 ; $i < ($self->{'num_datapoints'}) ; $i++) 
    {
        if ( length($data->[1][$i]) > $l2  ) 
        {
            $l2 = length($data->[1][$i]);
        }
    }

    if ($self->{'legend_label_values'} =~ /^value$/i ) 
    {
        $max_label_len = $l1 + $l2 +1;
    }
    elsif ($self->{'legend_label_values'} =~ /^percent$/i ) 
    {
        $max_label_len = $l1 +7;
    }
    elsif ($self->{'legend_label_values'} =~ /^both$/i ) 
    {
        $max_label_len = $l1 + $l2 +9;
    }
    else 
    {
        $max_label_len = $l1;
    }

    # figure out how wide the columns can be, and how many will fit
    $empty_width = ($x2 - $x1) - (2 * $self->{'legend_space'});
    $max_label_width = (4 * $self->{'text_space'})
    # + ($self->{'max_legend_label'} * $w)
    + $max_label_len * $w
    + $self->{'legend_example_size'};
    $cols = int ($empty_width / $max_label_width);
    
    unless ($cols) 
    {
        $cols = 1;
    }
    $col_width = $empty_width / $cols;

    # figure out how many rows we need and remember how tall they are
    $rows = int ($self->{'num_datapoints'} / $cols);
    unless (($self->{'num_datapoints'} % $cols) == 0) 
    {
        $rows++;
    }
    unless ($rows) 
    {
        $rows = 1;
    }
    $row_height = $h + $self->{'text_space'};

    # box the legend off
    $y1 = $self->{'curr_y_min'};
    $y2 = $self->{'curr_y_min'} + $self->{'text_space'}
          + ($rows * $row_height) + (2 * $self->{'legend_space'});
    $self->{'gd_obj'}->rectangle($x1, $y1, $x2, $y2,
                               $self->_color_role_to_index('misc'));

    # leave some space inside the legend
    $x1 += $self->{'legend_space'} + $self->{'text_space'};
    $x2 -= $self->{'legend_space'};
    $y1 += $self->{'legend_space'} + $self->{'text_space'};
    $y2 -= $self->{'legend_space'} + $self->{'text_space'};

    # draw in the actual legend
    for $r (0..$rows-1) 
    {
        for $c (0..$cols-1) 
        {
            $index = ($r * $cols) + $c;  # find the index in the label array
            if ($labels[$index]) 
            {
	        # get the color
                $color = $self->_color_role_to_index('dataset'.$index);

	        # find the x-y coords
	        $x = $x1 + ($col_width * $c);
                $y = $y1 + ($row_height * $r) + $h/2;

	        # draw the line first
                $self->{'gd_obj'}->line($x, $y,
                                $x + $self->{'legend_example_size'}, $y,
                                $color);

                # reset the brush for points
                $brush = $self->_prepare_brush($color, 'point',
				$self->{'pointStyle' . $index});
                $self->{'gd_obj'}->setBrush($brush);
        
                # draw the point
                $x3 = int($x + $self->{'legend_example_size'}/2);
                $self->{'gd_obj'}->line($x3, $y, $x3, $y, gdBrushed);

                # now the label
	        $x += $self->{'legend_example_size'} + (2 * $self->{'text_space'});
	        $y -= $h/2;
                if ( $self->{'legend_label_values'} =~ /^value$/i ) 
                {
                    $self->{'gd_obj'}->string($font, $x, $y, $labels[$index].' '.$data->[1][$index], $color);
                }
                elsif ( $self->{'legend_label_values'} =~ /^percent$/i ) 
                {
                    $label = sprintf("%s %4.2f%%",$labels[$index], $data->[1][$index] / ($dataset_sum || 1) * 100);
                    $self->{'gd_obj'}->string($font, $x, $y, $label, $color);
                }
                elsif ( $self->{'legend_label_values'} =~ /^both$/i ) 
                {
                    if ( $data->[1][$index] =~ /\./) 
                    {
                        $label = sprintf("%s %4.2f%% %.2f",$labels[$index], $data->[1][$index] / ($dataset_sum || 1) * 100, $data->[1][$index]);
                    }
                    else 
                    {
                        $label = sprintf("%s %4.2f%% %d",$labels[$index], $data->[1][$index] / ($dataset_sum || 1) * 100, $data->[1][$index]);
                    }
                    $self->{'gd_obj'}->string($font, $x, $y, $label, $color);
                }
                else 
                {
                    $self->{'gd_obj'}->string($font, $x, $y, $labels[$index], $color);
                }
            }
        }
    }

    # mark off the space used
    $self->{'curr_y_min'} += ($rows * $row_height) + $self->{'text_space'}
			      + 2 * $self->{'legend_space'};

    # now return
    return 1;
}

# Override the ticks methods for the pie charts
# as they do not always make sense.
sub _draw_x_ticks {
  my $self = shift;

  return;
}
sub _draw_y_ticks {
  my $self = shift;

  return;
}

sub _find_y_scale {
  my $self = shift;

  return;
}



## finally get around to plotting the data
sub _draw_data {
    my $self = shift;
    my $data = $self->{'dataref'};
    my $misccolor = $self->_color_role_to_index('misc');
    my $textcolor = $self->_color_role_to_index('text');
    my $background = $self->_color_role_to_index('background');
    my ($width, $height, $centerX, $centerY, $diameter, $text_diameter);
    my $dataset_sum;
    my ($start_degrees, $end_degrees, $label_degrees, $labelY_repeat_count);
    my $max_label_len;
    my ($pi, $rd2dg, $dg2rd); 
    my ($font, $fontW, $fontH, $labelX, $labelY);
    my $label;
    my ($i, $j, $color);
    my $label_length; 
    my $degrees=0;
    my $insidecolor;
    my $forbidden_degrees = 0;   # last occupied degree
    my %labelinfo;              
 
    # set up initial constant values
    $pi = 3.14159265;
    $dg2rd = $pi/180;   # Degree to Radians
    $rd2dg = 180/$pi;   # Radian to Degree
    $start_degrees=0;
    $end_degrees=0;
    $font = $self->{'legend_font'};
    $fontW = $self->{'legend_font'}->width;
    $fontH = $self->{'legend_font'}->height;
    $label_degrees = $labelY_repeat_count = 0;
  

    # init the imagemap data field if they wanted it
    if ($self->{'imagemap'} =~ /^true$/i) 
    {
        $self->{'imagemap_data'} = [];
    }

    # find width and height
    $width = $self->{'curr_x_max'} - $self->{'curr_x_min'};
    $height = $self->{'curr_y_max'} - $self->{'curr_y_min'};

 
    # okay, add up all the numbers of all the datasets, to get the
    # sum total. This will be used to determine the percentage 
    # of each dataset. Obviously, negative numbers might be bad :)
    $dataset_sum = 0;
    for $j (0..$self->{'num_datapoints'}) 
    {
    
        if(defined $data->[1][$j])
        {  
            #add to sum
            $dataset_sum += $data->[1][$j];
            #don't allow negativ values
            if ($data->[1][$j] < 0) 
            {
                croak "We need positiv data for a pie chart (which is not true for data[$j])!";
            }
        }
    }
   
    # find the longest label
    # first we need the length of the values
    $max_label_len = 1;
    for $j (0..($self->{'num_datapoints'}-1)) 
    {
        # don't try to draw anything if there's no data
        $labelinfo{$j}{data} = 'undefined';
        if (defined ($data->[1][$j])) 
        {
            $labelinfo{$j}{data} = $data->[1][$j];
            $label = $data->[0][$j];
            $labelinfo{$j}{labeldata} = $label;
            
            if( defined $self->{'label_values'})  
            {
                if($self->{'label_values'} =~ /^percent$/i)
                {
                    $label = sprintf("%s %4.2f%%",$label, $data->[1][$j] / ($dataset_sum || 1)  * 100);
                }
                elsif($self->{'label_values'} =~ /^value$/i)
                {
                    if ($data->[1][$j] =~ /\./) 
                    {
                        $label = sprintf("%s %.2f",$label, $data->[1][$j]);
                    }
                    else 
                    {
                        $label = sprintf("%s %d",$label,$data->[1][$j]);
                    }
                }
                elsif ($self->{'label_values'} =~ /^both$/i)
                {
                    if ($data->[1][$j] =~ /\./) 
                    {
                        $label = sprintf("%s %4.2f%% %.2f",$label,
                                          $data->[1][$j] / ($dataset_sum || 1)* 100,
                                          $data->[1][$j]);
                    }
                    else 
                    {
                        $label = sprintf("%s %4.2f%% %d",$label,
                                          $data->[1][$j] / ($dataset_sum || 1) * 100,
                                          $data->[1][$j]);
                    }
                }
                elsif($self->{'label_values'} =~ /^none$/i)
                {
                    $label = sprintf("%s",$label);
                }
            }
	    $label_length = length($label);
	    $labelinfo{$j}{labelstring} = $label,
            $labelinfo{$j}{labellength} = $label_length;
         
       }
       $max_label_len = $label_length if ( $max_label_len < $label_length );
    }
    $max_label_len *= $fontW;

    # find center point, from which the pie will be drawn around
    $centerX = int($width/2)  + $self->{'curr_x_min'};
    $centerY = int($height/2) + $self->{'curr_y_min'};

    # always draw a circle, which means the diameter will be the smaller
    # of the width and height. let enougth space for the labels
  
    my $labeldistance = 2*$self->maximum($fontW,$fontH);
    $diameter = $self->minimum($width,$height) - 2*$max_label_len - $labeldistance;

    # make sure, that we have a positive diameter
    if ($diameter < 0) 
    {
        croak "I have calculated a negative diameter for the pie chart, maybe your labels are too long or the picture is too small.";
    }
  
    $text_diameter = $diameter + $labeldistance;			       
    $self->{'gd_obj'}->arc($centerX, $centerY, $diameter, $diameter,
                               0, 360, $misccolor);
    # for DEBUG!!
    #$self->{'gd_obj'}->arc($centerX, $centerY, $text_diameter, $text_diameter,
    #                           0, 360, $misccolor);

    for $j (0..($self->{'num_datapoints'}-1)) 
    {
        #next if $labelinfo{$j}{data} eq 'undefined';
        # get the color for this datapoint, take the color of the datasets
        $color = $self->_color_role_to_index('dataset'.$j);
   
        $label = $labelinfo{$j}{labelstring};
        $label_length = $labelinfo{$j}{labellength};

        # The first value starts at 0 degrees, each additional dataset
        # stops where the previous left off, and since I've already 
        # calculated the sum_total for the whole graph, I know that
        # the final pie slice will end at 360 degrees.

        # So, get the degree offset for this dataset
        $end_degrees = $start_degrees + ($data->[1][$j] / ($dataset_sum || 1)  * 360);
    
        $degrees = $start_degrees+($end_degrees-$start_degrees)/2;
  
        # stick the label in the middle of the slice
        $label_degrees = ($start_degrees + $end_degrees) / 2;

        # The following drawings are in a very specific ordering, and are not
        # intuitive as to why they are being done this way, but it is basically
        # because the GD module doesn't provide a filledArc() method. So, I
        # developed my own, below.
 
        # First, draw an arc, in black, from the starting offset, all the 
        # way to 360 degrees.
        $self->{'gd_obj'}->arc($centerX,$centerY,
                                $diameter, $diameter,
                                $start_degrees, 360,
                                $misccolor);

        # This is tricky, but draw a short line in the desired color, along the
        # path that will be the end of this pie slice of data. But, make sure not
        # to extend this line to intersect with the boundary of the arc. This
        # is crucial.
        if ( $start_degrees != $end_degrees )
        {
            $self->{'gd_obj'}->line($centerX, $centerY,
                                    $centerX + .4*$diameter*cos($end_degrees*$dg2rd),
                                    $centerY + .4*$diameter*sin($end_degrees*$dg2rd),
                                    $color);
            # Draw the radius of the beginning side of the pie slice, in black
            $self->{'gd_obj'}->line($centerX,$centerY,
                        $centerX + .5*$diameter*cos($start_degrees*$dg2rd),
                        $centerY + .5*$diameter*sin($start_degrees*$dg2rd),
                        $misccolor);
 

            # Now, execute fillToBorder, starting from a point on the end line, in the
            # desired pie slice color, and fill until a black pixel if encountered.
            # What this means, is that a series of pie slices is drawn, each starting
            # at the correct location, but each ending at 360 degrees. 
    
            $self->{'gd_obj'}->fillToBorder(
                                            $centerX + .4*$diameter*cos($end_degrees*$dg2rd),
                                            $centerY + .4*$diameter*sin($end_degrees*$dg2rd),
                                            $misccolor, $color
                                           );
        }
        # Figure out where to place the label
        if ( $j == 0 )
        {
            $forbidden_degrees = $rd2dg*atan2($fontH,0.5*$text_diameter);
        }
        else
        { 
            $label_degrees = $self->maximum($label_degrees,$forbidden_degrees);
            my $winkel = cos($label_degrees*$dg2rd);
            my $h;
            
            $winkel = abs($winkel);
            if ( abs($winkel) < 0.01 )
            {
               $h    = 0;
            }
            else
            {
               $h    = $fontH/$winkel;
            }
            
            my $atan = atan2($h,0.5*$text_diameter); #  -pi ... +pi

            #print $j.",". $atan*$rd2dg.",".cos($label_degrees*$dg2rd).",".$h.",".$label_degrees."\n";
            
            $forbidden_degrees = $label_degrees + $rd2dg*$atan;
            
        }
        $labelX = $centerX+$text_diameter*0.5*cos($label_degrees*$dg2rd);
        $labelY = $centerY+$text_diameter*0.5*sin($label_degrees*$dg2rd);
        
        #        # For debugging
        #        # Draw Point
        #        # reset the brush for points
        #        my $brush = $self->_prepare_brush($color, 'point',
	#			$self->{'pointStyle' . '0'});
        #        $self->{'gd_obj'}->setBrush($brush);
        # 
        #        # draw the point
        #        $self->{'gd_obj'}->line($labelX, $labelY, $labelX, $labelY, gdBrushed);
        #        # end for debugging

        # Okay, if a bunch of very small datasets are close together, they can
        # overwrite each other. The following if statement is to help keep
        # labels of neighbor datasets from being overlapped. It ain't perfect,
        # but it does a pretty good job.
	
        if ( ($label_degrees >= 270 && $label_degrees <= 360) || 
             ($label_degrees >= 0   && $label_degrees <= 90 ) )
        {
            # right side of the circle
            # as 0 degrees means east
            $self->{'gd_obj'}->string($font, $labelX, $labelY-$fontH*0.5, 
                                      $label, $textcolor); # $textcolor would mark everything black
            
        }
        else
        {
            $self->{'gd_obj'}->string($font, $labelX-length($label)*$fontW, $labelY-$fontH*0.5, 
                                      $label, $textcolor); # $textcolor would mark everything black
        }
  
        if ($self->{'legend_lines'} =~ /^true$/i) 
        {
            $self->{'gd_obj'}->line(
                                    $centerX+0.5*$diameter*cos($degrees*$dg2rd),
		                    $centerY+0.5*$diameter*sin($degrees*$dg2rd),
		                    $labelX, $labelY, $color
                                   );                 
        }	    
       
        # reset starting point for next dataset and continue.    
        $start_degrees      = $end_degrees;
    }
  
  
  
    # print "Center $centerX, $centerY\n";
    # print "Durchmesser $diameter\n";
    # print "Hintergrund $background\n";  
  
    if ( defined($self->{'ring'}) &&  abs($self->{'ring'}) < 1 ) 
    {
        # print "bground $bground\n";
        my $hole = (1- abs($self->{'ring'}));
        if ($self->{'grey_background'} =~ /^true$/i) 
        {
            $insidecolor = $self->_color_role_to_index('grey_background');
        }
        else 
        {
            $insidecolor = $background;
        }  
   
		       
        $self->{'gd_obj'}->filledArc($centerX, $centerY, 
                               $hole*$diameter, 
                               $hole*$diameter,
                               0, 360, $insidecolor);
			       
        $self->{'gd_obj'}->arc($centerX, $centerY, 
                               $hole*$diameter, 
                               $hole*$diameter,
                               0, 360, $misccolor);			       
  
    }
  
  
  
    # and finaly box it off 
  
 
    $self->{'gd_obj'}->rectangle ($self->{'curr_x_min'},
                                $self->{'curr_y_min'},
                                $self->{'curr_x_max'},
                                $self->{'curr_y_max'},
                                $misccolor);
    return;

}


## be a good module and return 1
1;
