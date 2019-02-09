breed [halos halo]

breed [targets target]
breed [searchers searcher]
breed [independents independent]
breed [malicious_entities malicious_entitity]
breed [detectors detector]

turtles-own
[
  received_sequence_number_target_type_0
  received_distance_to_target_type_0

  received_sequence_number_target_type_1
  received_distance_to_target_type_1

  comms_range                     ; distance entity can transmit communications to other entites
  speed                           ; 0.15m/s  in paper - except for target which is zero
  step_size_scaling               ; used to scale size of area
]

patches-own
[
  wall_here
  jamming_here
  environment_status ; -10 wall, 0 nothing no jamming, >0 jamming
]

targets-own
[
  target_type
  target_sequence_number          ; s(T)
]

searchers-own
[
  distance_to_best_neighbour      ; d(A,B)
  searching_for_target_type
  estimate_distance_to_target_0
  new_estimate_distance_to_target_0
  estimate_distance_to_target_1
  new_estimate_distance_to_target_1
  own_distance_travelled
]

detectors-own
[
  visable_targets ; record of current visable targets to check on
  suspicious_activity; suspect malicious activity true/false

  distance_to_best_neighbour      ; d(A,B)
  searching_for_target_type
  estimate_distance_to_target_0
  new_estimate_distance_to_target_0
  estimate_distance_to_target_1
  new_estimate_distance_to_target_1
  own_distance_travelled

  target_count

  own_distance_to_move
]

independents-own
[
  own_distance_to_move
]

malicious_entities-own
[
  distance_to_best_neighbour      ; d(A,B)
  searching_for_target_type
  estimate_distance_to_target_0
  new_estimate_distance_to_target_0
  estimate_distance_to_target_1
  new_estimate_distance_to_target_1
  own_distance_travelled

  jammer
  started_jamming
  jamming_active
  jamming_period_remaining

  own_distance_to_move
]

globals
[
  target_found
  malicious_cleared
  comms_broadcast_update          ; 0.1sec in paper - Thought: Set 1 tick = time step i.e. 0.1 sec

  targets_x_position
  targets_y_position

  good_find ; Kill a malicious entity
  false_positives ; Kill a non-malicious entity
  false_negatives ; Don't kill a detected maklicious entity

]

to update_sequence_number_at_target
  ask targets
  [
    set target_sequence_number (target_sequence_number + 1)
  ]
end



to move_malicious_entities
  let distance_moved 0
  ask malicious_entities
  [
    if (own_distance_to_move <= 0 ) ; set_random_move
    [
      set heading (random-float 360)
      set own_distance_to_move ((random-exponential 10) * speed) ; set for 10 seconds - from paper section 3.2
    ]

    set distance_moved (speed * comms_broadcast_update) ;
    check_wall_collision (distance_moved)
    forward (distance_moved)
    set own_distance_to_move (own_distance_to_move - distance_moved)
    set received_distance_to_target_type_0 (received_distance_to_target_type_0 + distance_moved)
    set received_distance_to_target_type_1 (received_distance_to_target_type_1 + distance_moved)
  ]
end

to move_independents
  let distance_moved 0
  ask independents
  [
    if (own_distance_to_move <= 0 ) ; set_random_move
    [
      set heading (random-float 360)
      set own_distance_to_move ((random-exponential 10) * speed) ; set for 10 seconds - from paper section 3.2
    ]

    set distance_moved (speed * comms_broadcast_update)
    check_wall_collision (distance_moved)
    forward (distance_moved)
    set own_distance_to_move (own_distance_to_move - distance_moved)
    set received_distance_to_target_type_0 (received_distance_to_target_type_0 + distance_moved)
    set received_distance_to_target_type_1 (received_distance_to_target_type_1 + distance_moved)
  ]
end

to move_searchers
  let distance_moved 0
  ask searchers
  [
    ifelse (distance_to_best_neighbour > 0)
    [
      set distance_moved (speed * comms_broadcast_update)
      check_wall_collision (distance_moved)
      forward distance_moved
      set distance_to_best_neighbour (distance_to_best_neighbour - distance_moved)
      set received_distance_to_target_type_0 (received_distance_to_target_type_0 + distance_moved)
    ]
    [
      if (searcher_mode = "Move Randomly")
      [
        set heading (random-float 360)
        set distance_to_best_neighbour ((random-exponential 10) * speed) ; set for 10 seconds - from paper section 3.2
        set distance_moved (speed * comms_broadcast_update)
        check_wall_collision (distance_moved)
        forward distance_moved
        set distance_to_best_neighbour (distance_to_best_neighbour - distance_moved)
      ]
      ; if it is not Move Randomly - wait until receives new command with neighbour information
    ]
  ]
end

to detectors_update

  let distance_to_move 0

  let temp_list []; empty list to work with
  let temp_distance 0
  let temp_bearing 0
  let new_distance 0
  let new_bearing 0
  let angle 0

  let number_check 0


  ask detectors
  [
    set visable_targets []
    set distance_to_move (speed * comms_broadcast_update)

    foreach sort in_comms_range_entities
    [
      if possible_comms ?
      [
        set temp_list[]
        create-link-with ?
        set temp_distance distance ?
        set temp_bearing bearing-of-neighbour(?)
        set angle abs(temp_bearing - heading)
        if (angle > 180)
        [
          set angle (360 - angle)
        ]

        set new_distance sqrt((temp_distance ^ 2) + (distance_to_move ^ 2) - ((2 * temp_distance * distance_to_move) * cos angle))

        set number_check (((new_distance ^ 2) + (distance_to_move ^ 2) - (temp_distance ^ 2)) / (2 * new_distance * distance_to_move))

        if ((number_check >= -1) and (number_check <= 1)) ; to ensure acos received a correct number in all circumstances (between -1 and +1)
        [
          set new_bearing 180 - acos (number_check)
        ]

        set temp_list lput new_distance temp_list
        set temp_list lput new_bearing temp_list
        set visable_targets lput temp_list visable_targets

      ]
    ]
  ]

end

to move_detectors

  let distance_moved 0
  ask detectors
  [
    if (own_distance_to_move <= 0 ) ; set_random_move
    [
      set heading (random-float 360)
      set own_distance_to_move ((random-exponential 10) * speed) ; set for 10 seconds - from paper section 3.2
    ]
    set distance_moved (speed * comms_broadcast_update)
    check_wall_collision (distance_moved)
    forward (distance_moved)
    set own_distance_to_move (own_distance_to_move - distance_moved)
    set received_distance_to_target_type_0 (received_distance_to_target_type_0 + distance_moved)
    set received_distance_to_target_type_1 (received_distance_to_target_type_1 + distance_moved)
  ]

end

to update_independents
  ask independents
  [
    foreach sort in_comms_range_entities
    [
      if possible_comms ?
      [
        create-link-with ?

        let local_target_found FALSE
        let temp_target_type_found 0

        let rxed_sequence_number 0
        let rxed_est_dist_to_target 0
        let temp_dist 0

        ask ?
        [
          if (breed = targets)
          [
            set temp_target_type_found target_type
            if(temp_target_type_found = 0)
            [
              set received_sequence_number_target_type_0 target_sequence_number
            ]
            if(temp_target_type_found = 1)
            [
              set received_sequence_number_target_type_1 target_sequence_number
            ]
          ]
          set rxed_sequence_number received_sequence_number_target_type_0
          set rxed_est_dist_to_target received_distance_to_target_type_0
          set temp_dist (received_distance_to_target_type_0 + distance myself)
        ]

        if ((rxed_sequence_number > received_sequence_number_target_type_0)
        or ((rxed_sequence_number = received_sequence_number_target_type_0) and (temp_dist < received_distance_to_target_type_0)))
        [
          set received_sequence_number_target_type_0 rxed_sequence_number
          set received_distance_to_target_type_0 temp_dist
        ]
      ]
    ]
  ]
end

to update_searchers
  ask searchers
  [
    foreach sort in_comms_range_entities
    [
      if possible_comms ?
      [
        create-link-with ?

        let local_target_found FALSE
        let temp_target_type_found 0

        let rxed_sequence_number_target_type_0 0
        let rxed_est_dist_to_target_type_0 0
        let temp_dist_target_type_0 0

        let rxed_sequence_number_target_type_1 0
        let rxed_est_dist_to_target_type_1 0
        let temp_dist_target_type_1 0

        ask ?
        [
          if (breed = targets)
          [
            set temp_target_type_found target_type
            if(temp_target_type_found = 0)
            [
              set received_sequence_number_target_type_0 target_sequence_number
              set received_distance_to_target_type_0 0 ; as distance myself follows
            ]
            if(temp_target_type_found = 1)
            [
              set received_sequence_number_target_type_1 target_sequence_number
              set received_distance_to_target_type_1 0 ; as distance myself follows
            ]
            if((temp_target_type_found = 3) and (distance myself < 0.5))
            [
              set target_found TRUE
              stop
            ]
            if((distance myself) < 0.5)
            [
              set local_target_found TRUE
            ]
          ]
          set rxed_sequence_number_target_type_0 received_sequence_number_target_type_0
          set rxed_est_dist_to_target_type_0 received_distance_to_target_type_0
          set temp_dist_target_type_0 (received_distance_to_target_type_0 + distance myself)

          set rxed_sequence_number_target_type_1 received_sequence_number_target_type_1
          set rxed_est_dist_to_target_type_1 received_distance_to_target_type_1
          set temp_dist_target_type_1 (received_distance_to_target_type_1 + distance myself)
        ]

        if((local_target_found = TRUE) and (temp_target_type_found = searching_for_target_type))
        [
          ifelse(searching_for_target_type = 0)
          [
            set searching_for_target_type 1
            set color BLUE
          ]
          [
            set searching_for_target_type 0
            set color YELLOW
          ]
        ]

        if ((rxed_sequence_number_target_type_0 > received_sequence_number_target_type_0)
        or ((rxed_sequence_number_target_type_0 = received_sequence_number_target_type_0) and (temp_dist_target_type_0 < received_distance_to_target_type_0)))
        [
          set own_distance_travelled (0)

          set received_sequence_number_target_type_0 rxed_sequence_number_target_type_0
          set received_distance_to_target_type_0 temp_dist_target_type_0
          if (searching_for_target_type = 0)
          [
            face ?
            set distance_to_best_neighbour (distance ?)
          ]
        ]

        if ((rxed_sequence_number_target_type_1 > received_sequence_number_target_type_1)
        or ((rxed_sequence_number_target_type_1 = received_sequence_number_target_type_1) and (temp_dist_target_type_1 < received_distance_to_target_type_1)))
        [
          set own_distance_travelled (0)

          set received_sequence_number_target_type_1 rxed_sequence_number_target_type_1
          set received_distance_to_target_type_1 temp_dist_target_type_1

          if (searching_for_target_type = 1)
          [
            face ?
            set distance_to_best_neighbour (distance ?)
          ]
        ]
      ]
    ]
  ]
end

to detectors_suspicion_check ; get the detectors to look for uncharacteristic behaviours

  let working_list []

  let temp_list []; empty list to work with
  let temp_distance 0
  let temp_bearing 0
  let previous_distance 0
  let previous_bearing 0
  let angle 0

  let check_count FALSE

  let target_detected FALSE

  ask detectors
  [
    foreach sort in_comms_range_entities
    [
      if possible_comms ?
      [

        set working_list visable_targets ; copy the previous known entities into a working list
        create-link-with ?

        set temp_distance distance ? ; initially round
        set temp_bearing bearing-of-neighbour(?)
        foreach (working_list)
        [
          set previous_distance (item 0 ?)

          if (abs(temp_distance - previous_distance) <= detection_accuracy_range)
          [
            set angle abs(temp_bearing - heading)
            if (angle > 180)
            [
              set angle (360 - angle)
            ]
            set previous_bearing (item 1 ?)

            if (abs(angle - previous_bearing) <= detection_accuracy_angle)
            [
              set target_detected TRUE
            ]
          ]
        ]
        ask ?
        [
          if ((breed = malicious_entities) and (target_detected = TRUE))
          [
            set good_find (good_find + 1) ; target found and detected
            die
            set target_detected FALSE
          ]
          if ((breed != malicious_entities) and (target_detected = TRUE))
          [
            set false_positives (false_positives + 1) ; other entity found, believed to be a malicious entity
            die
            set target_detected FALSE
          ]
          if ((breed = malicious_entities) and (target_detected = FALSE))
          [
            set check_count TRUE
          ]

        ]

        if(check_count = TRUE)
        [
          set target_count (target_count + 1)
          if (target_count > 1)
          [
            set false_negatives (false_negatives + 1)  ; Target detected but not believed to be a malicious entity
            set target_count 0
          ]
          set check_count FALSE
          set target_detected FALSE
        ]

        set target_detected FALSE
      ]
    ]
  ]

end


to-report in_comms_range_entities

  ifelse (jamming_attackers_visable = "TRUE")
  [
    report other ((turtle-set searchers independents targets malicious_entities) in-radius (comms_range))
  ]
  [
    report other ((turtle-set searchers independents targets) in-radius (comms_range))
  ]

end



to jam_communications

  ask malicious_entities with [(jammer = TRUE) AND (jamming_active = FALSE)] ; Clear jamming before adding existing/new jamming
  [
    if (started_jamming = TRUE)
    [
      set started_jamming FALSE
    ]

    if (jamming_period_remaining = 0)
    [
      if random 100 < chance_of_jamming
      [
        set jamming_period_remaining (jamming_period)
        set jamming_active TRUE
      ]
    ]
  ]

  ask malicious_entities with [jamming_active = TRUE]
    [
      if (jamming_period_remaining > 0)
      [

        jamming_effect (TRUE) ; Needed incase cleared above
        colour_check_patches
        set started_jamming TRUE

        set jamming_period_remaining jamming_period_remaining - 1
        if (jamming_period_remaining = 0)
        [
          set jamming_active FALSE
        ]
      ]
    ]
end

to move_jammers
  ask malicious_entities with [started_jamming = TRUE]
  [
    jamming_effect (FALSE)
  ]
  move_malicious_entities
end

to jamming_effect [action]

  let number_change 1

  ifelse (action = TRUE) ; TRUE = jamming, FALSE = remove jamming effect
  [

  ]
  [
    set number_change -1
  ]
  ask patch-here [set environment_status environment_status + number_change]

  ifelse any? patches in-radius jamming_range_malicious with [pcolor = blue]
  [
    let possible_area patches in-radius jamming_range_malicious

    ;; WALL DETECTED, FIND OPEN SPACE OR WALL

    let centre_point patch-here
    ask centre_point [set environment_status environment_status + number_change]

    let completed_search FALSE
    let wall_found  FALSE

    let test_patch patch-at 0 0
    let x-offset 0
    let y-offset 0

    let check 0

    while [completed_search = FALSE]
    [
      ; NORTH
      set check check_North 0 1 possible_area number_change

      ; SOUTH
      set check check_South 0 -1 possible_area number_change

      ; EAST
      set check check_East 1 0 possible_area number_change

      ; WEST
      set check check_West -1 0 possible_area number_change

      ; CHECK TO THE NORTH EAST
      check_North_East 1 1 possible_area number_change

      ; CHECK TO THE SOUTH EAST
      check_South_East 1 -1 possible_area number_change

      ; CHECK TO THE SOUTH WEST
      check_South_West -1 -1 possible_area number_change

      ; CHECK TO THE NORTH WEST
      check_North_West -1 1 possible_area number_change

      set completed_search TRUE
    ]
  ]
  [
    ask patches in-radius jamming_range_malicious [set environment_status environment_status + number_change]
  ]
end

to-report check_North [x-offset y-offset possible_area number_change]
  while [([pcolor] of patch-at x-offset y-offset != blue) and (member? (patch-at x-offset y-offset) possible_area)]
  [
    ask patch-at x-offset y-offset [set environment_status environment_status + number_change]
    set y-offset y-offset + 1
  ]

  ifelse ([pcolor] of patch-at x-offset y-offset = blue)
  [
    report -2
  ]
  [
    report -1
  ]
end

to-report check_South [x-offset y-offset possible_area number_change]
  while [([pcolor] of patch-at x-offset y-offset != blue) and (member? (patch-at x-offset y-offset) possible_area)]
  [
    ask patch-at x-offset y-offset [set environment_status environment_status + number_change]
    set y-offset y-offset - 1
  ]

  ifelse ([pcolor] of patch-at x-offset y-offset = blue)
  [
    report -2
  ]
  [
    report -1
  ]
end

to-report check_East [x-offset y-offset possible_area number_change]
  while [([pcolor] of patch-at x-offset y-offset != blue) and (member? (patch-at x-offset y-offset) possible_area)]
  [
    ask patch-at x-offset y-offset [set environment_status environment_status + number_change]
    set x-offset x-offset + 1
  ]

  ifelse ([pcolor] of patch-at x-offset y-offset = blue)
  [
    report -2
  ]
  [
    report -1
  ]
end

to-report check_West [x-offset y-offset possible_area number_change]
  while [([pcolor] of patch-at x-offset y-offset != blue) and (member? (patch-at x-offset y-offset) possible_area)]
  [
    ask patch-at x-offset y-offset [set environment_status environment_status + number_change]
    set x-offset x-offset - 1
  ]
    ifelse ([pcolor] of patch-at x-offset y-offset = blue)
  [
    report -2
  ]
  [
    report -1
  ]
end

to check_North_West [x-offset y-offset possible_area number_change]
    let x-run 0
    let y-run 0
    let start_offset 0
    let x-count 0
    let y-count 0
    let angle_offset 270

    let continue TRUE

    while [([pcolor] of patch-at x-offset y-offset != blue) and (continue = TRUE) and ((pxcor + x-offset) > min-pxcor) and ((pycor + y-offset) < max-pycor)]
    [

      while[(continue = TRUE) and (member? (patch-at x-offset y-offset) possible_area)]
      [
        set x-count x-count + 1

        set x-run check_North x-offset y-offset possible_area number_change
        if ((x-run = -1) or (x-run = -2))
        [
          set continue FALSE
        ]
        set x-offset x-offset - 1
      ]

      while[(member? (patch-at x-offset y-offset) possible_area) and (continue = FALSE)]
      [
        set continue TRUE
      ]

      while[(continue = TRUE) and (member? (patch-at x-offset y-offset) possible_area)]
      [
        set y-count y-count + 1

        set y-run check_West x-offset y-offset possible_area number_change
        if ((y-run = -1) or (y-run = -2))
        [
          set continue FALSE
        ]
        set y-offset y-offset + 1 ; eventually hits wall or area limits
      ]

    ]

    fill_in_due_to_wall start_offset angle_offset y-count x-count number_change
end

to check_North_East [x-offset y-offset possible_area number_change]
    let x-run 0
    let y-run 0
    let start_offset 0
    let x-count 0
    let y-count 0
    let angle_offset 0

    let continue TRUE

    while [([pcolor] of patch-at x-offset y-offset != blue) and (continue = TRUE) and ((pxcor + x-offset) < max-pxcor) and ((pycor + y-offset) < max-pycor)]
    [

      while[(continue = TRUE) and (member? (patch-at x-offset y-offset) possible_area)]
      [
        set x-count x-count + 1

        set x-run check_North x-offset y-offset possible_area number_change
        if ((x-run = -1) or (x-run = -2))
        [
          set continue FALSE
        ]
        set x-offset x-offset + 1
      ]

      while[(member? (patch-at x-offset y-offset) possible_area) and (continue = FALSE)]
      [
        set continue TRUE
      ]

      while[(continue = TRUE) and (member? (patch-at x-offset y-offset) possible_area)]
      [
        set y-count y-count + 1

        set y-run check_East x-offset y-offset possible_area number_change
        if ((y-run = -1) or (y-run = -2))
        [
          set continue FALSE
        ]
        set y-offset y-offset + 1 ; eventually hits wall or area limits
      ]

    ]

    fill_in_due_to_wall start_offset angle_offset x-count y-count number_change
end

to check_South_East [x-offset y-offset possible_area number_change]
    let x-run 0
    let y-run 0
    let start_offset 0
    let x-count 0
    let y-count 0
    let angle_offset 90

    let continue TRUE

    while [([pcolor] of patch-at x-offset y-offset != blue) and (continue = TRUE) and ((pxcor + x-offset) < max-pxcor) and ((pycor + y-offset) > min-pycor)]
    [

      while[(continue = TRUE) and (member? (patch-at x-offset y-offset) possible_area)]
      [

        set x-count x-count + 1

        set x-run check_South x-offset y-offset possible_area number_change
        if ((x-run = -1) or (x-run = -2))
        [
          set continue FALSE
        ]
        set x-offset x-offset + 1
      ]

      while[(member? (patch-at x-offset y-offset) possible_area) and (continue = FALSE)]
      [
        set continue TRUE
      ]

      while[(continue = TRUE) and (member? (patch-at x-offset y-offset) possible_area)]
      [
        set y-count y-count + 1

        set y-run check_East x-offset y-offset possible_area number_change
        if ((y-run = -1) or (y-run = -2))
        [
          set continue FALSE
        ]
        set y-offset y-offset - 1 ; eventually hits wall or area limits
      ]
    ]

    fill_in_due_to_wall start_offset angle_offset y-count x-count number_change
end

to check_South_West [x-offset y-offset possible_area number_change]

    let x-run 0
    let y-run 0
    let start_offset 0
    let x-count 0
    let y-count 0
    let angle_offset 180

    let continue TRUE

    while [([pcolor] of patch-at x-offset y-offset != blue) and (continue = TRUE) and ((pxcor + x-offset) > min-pxcor) and ((pycor + y-offset) > min-pycor)]
    [

      while[(continue = TRUE) and (member? (patch-at x-offset y-offset) possible_area)]
      [
        set x-count x-count + 1

        set x-run check_South x-offset y-offset possible_area number_change
        if ((x-run = -1) or (x-run = -2))
        [
          set continue FALSE
        ]
        set x-offset x-offset - 1
      ]

      while[(member? (patch-at x-offset y-offset) possible_area) and (continue = FALSE)]
      [
        set continue TRUE
      ]

      while[(continue = TRUE) and (member? (patch-at x-offset y-offset) possible_area)]
      [
        set y-count y-count + 1

        set y-run check_West x-offset y-offset possible_area number_change
        if ((y-run = -1) or (y-run = -2))
        [
          set continue FALSE
        ]
        set y-offset y-offset - 1 ; eventually hits wall or area limits
      ]
    ]

    fill_in_due_to_wall start_offset angle_offset x-count y-count number_change
end


to fill_in_due_to_wall [start_offset angle_offset distance_a distance_b number_change]

    let completed_search FALSE
    let possible_area patches in-radius jamming_range_malicious

    let direction_step (45 / (jamming_range_malicious + 1))
    let step_distance 1

    let start_angle_offset 0
    let end_angle_offset 0

    set start_angle_offset safe-atan distance_a jamming_range_malicious

    set start_angle_offset (floor(start_angle_offset / direction_step) * direction_step)

    let direction_check (angle_offset + start_angle_offset)

     while [completed_search = FALSE]
    [
       while [([pcolor] of patch-at-heading-and-distance direction_check step_distance != blue) and (member? (patch-at-heading-and-distance direction_check step_distance) possible_area)]
       [
         ask patch-at-heading-and-distance direction_check step_distance [set environment_status environment_status + number_change]
         set step_distance step_distance + 1
       ]

       set step_distance 1
       set direction_check (direction_check + (direction_step))

       if ((direction_check - angle_offset) >= 90)
       [
         set completed_search TRUE
       ]
    ]
end

to-report check_offset [x-run y-run]

  let start_offset 0

    ifelse (x-run != -1)  ; if x-run found a wall
    [
      ifelse (y-run != -1) ; if x-run and y-run found a wall
      [
        ifelse (x-run <= y-run)
        [
          set start_offset x-run ; if x-run the smallest
        ]
        [
          set start_offset y-run ; if y-run smallest number
        ]
      ]
      [
        set start_offset x-run ; y-run did not find a wall but x-run did
      ]
    ]
    [
      ifelse (y-run != -1) ; if x-run and y-run found a wall
      [
        set start_offset y-run ; x-run did not find a wall but y-run did
      ]
      [
        set start_offset -1
      ]
    ]
    report start_offset
end



to setup
  clear-all

  ;; the "thin ring" shape was made using the shapes editor;
  ;; it's a simple, unfilled circle
  set-default-shape halos "thin ring"

  let searcher_placed TRUE


  ask patches
  [
    set wall_here FALSE
    set jamming_here FALSE
    set environment_status 0
  ]
  draw_boundaries
  set comms_broadcast_update (1)
  if (maze_type != "None")
  [
    draw_maze
  ]
  reset-ticks
  display ; force display to update

  set searcher_placed place_searcher (2)       ; 2 - set distance from target, 0 - All the same (-1 = 50/50 for subtype for searching for)
  if (searcher_placed = FALSE)
  [
    setup
  ]

  place_independents (1)
  if( jamming_attack != "No Attack")
  [
    place_malicious_entities (1) ; - 1 Mobile (0) - 0 Fixed
  ]

  if(attack_to_detect = "stationary")
  [
    place_malicious_entities (10)
  ]

  place_detectors (1)

  set target_found FALSE
  set malicious_cleared FALSE

  set good_find 0 ; Kill a malicious entity
  set false_positives 0 ; Kill a non-malicious entity
  set false_negatives 0 ; Don't kill a detected maklicious entity

end


to go_single
        if(count malicious_entities = 0)
        [
          set malicious_cleared TRUE
          stop
        ]
        clear-links
        if(jamming_attack != "No Attack")
        [
          jam_communications
        ]

        detectors_update
        move_independents
        move_searchers
        update_independents
        update_searchers

        move_detectors
        detectors_suspicion_check

        update_sequence_number_at_target

        tick
end


to colour_check_patches
  ask patches with [(pxcor < max-pxcor) AND (pxcor > min-pxcor) AND (pycor < max-pycor) AND (pycor > min-pycor)]
  [
    ifelse environment_status = -10
    [
      set pcolor BLUE
    ]
    [
      ifelse environment_status > 0
      [
        set pcolor RED
      ]
      [
        set pcolor BLACK
      ]
    ]

  ]
end

to-report num-date  ; current date in numerical format, yyyy-mm-dd
  let $dt substring date-and-time 16 27
  report (word (substring $dt 7 11)           ; yyyy
           "-" (month-num substring $dt 3 6)  ; mm
           "-" (substring $dt 0 2) )          ; dd
end

to-report month-num [ #mon ]
  let $index 1 + position #mon
    ["Jan""Feb""Mar""Apr""May""Jun""Jul""Aug""Sep""Oct""Nov""Dec"]
  report substring (word (100 + $index)) 1 3  ; force 2-digit string
end

to go_exp

  let new_file_name ("")
  let date ""
  set date num-date
  let number_of_robots_list []


  let rounds (0)
  let count_to_find_target (0)
  let ave_time_to_find_target (0)

  let good_find_count (0)
  let average_good_finds (0)
  let false_positive_count (0)
  let average_false_positives (0)
  let false_negative_count (0)
  let average_false_negatives (0)

  set new_file_name (word File_Name "_" date ".csv")
  if (file-exists? new_file_name)
  [
    file-close
    file-delete new_file_name
  ]
  print (word "new_file_name: " new_file_name)
  file-open new_file_name
  file-print "Malicious Entity Quantity: "
  if (size_of_malicious_swarm = "small")[file-print "small"]
  if (size_of_malicious_swarm = "medium")[file-print "medium"]
  if (size_of_malicious_swarm = "large")[file-print "large"]
  file-print " "
  file-print "Number of rounds: "
  file-print number_of_rounds

  set number_of_robots_list [10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90] ; [5 10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90 95 100] ;
  let number_of_detectors_list [2] ; [1 2 3 4 5 6 7 8 9 10]

    foreach number_of_detectors_list
    [
      set number_of_detectors ?
      print (word "number_of_detectors_entities_list: " number_of_detectors)

      file-print " "
      file-print " "
      file-print " "
      file-print "Number of Detectors: "
      file-write number_of_detectors
      file-print " "
      file-print " "
      file-print "No of Ind , Ave time to clear , Good Finds , False Pos, False Neg"

      foreach number_of_robots_list
      [
        set number_of_independents ?

        print (word "number_of_independents: " number_of_independents)

        set target_found FALSE
        set malicious_cleared FALSE

        while [rounds < number_of_rounds]
        [
          setup

          print (word "rounds: " rounds)

          while [malicious_cleared = FALSE]
          [
            go_single
          ]

          set count_to_find_target (count_to_find_target + ( ticks ))

          set good_find_count (good_find_count + good_find)
          set false_positive_count (false_positive_count + false_positives)
          set false_negative_count (false_negative_count + false_negatives)

          set rounds (rounds + 1)
        ]

        set ave_time_to_find_target ((count_to_find_target / number_of_rounds))
        set average_good_finds (good_find_count / number_of_rounds)
        set average_false_positives (false_positive_count / number_of_rounds)
        set average_false_negatives (false_negative_count / number_of_rounds)



        print (word "Ave Time to Clear Malicious Entities: " ave_time_to_find_target)

        file-type number_of_independents
        file-type " ,"
        file-type ave_time_to_find_target
        file-type " ,"
        file-type average_good_finds
        file-type " ,"
        file-type average_false_positives
        file-type " ,"
        file-type average_false_negatives
        file-print " "
        file-flush

        set rounds (0)                   ; reset counters
        set ave_time_to_find_target (0)  ; reset counters
        set count_to_find_target (0)     ; reset counters

        set average_good_finds (0)
        set good_find_count (0)

        set average_false_positives (0)
        set false_positive_count (0)

        set average_false_negatives (0)
        set false_negative_count (0)
      ]
    ]

  file-close

end


to-report possible_comms [entity-under-observation]


    let seperation (distance entity-under-observation)
    let bearing (bearing-of-neighbour entity-under-observation)     ; bearing from entity under observation

    let steps floor (seperation / 0.5)

    let wall-found FALSE
    let jamming FALSE
    let comms_possible TRUE

    let initial_colour-check ([pcolor] of patch-here) ; initial check is incase an entity is already within a jamming area, wall included for completeness
    if initial_colour-check = BLUE
    [
      set comms_possible FALSE
    ]
    if initial_colour-check = RED
    [
      set comms_possible FALSE
    ]

    let moves 1

    while [(moves < steps) AND (comms_possible = TRUE)]
    [
      let colour-check [pcolor] of (patch-at-heading-and-distance bearing (0.5 * moves))
      set moves moves + 1
      if colour-check = BLUE
      [
        set comms_possible FALSE
      ]
      if colour-check = RED
      [
        set comms_possible FALSE
      ]
    ]

  report comms_possible

end

to draw_maze

  let x-position_current(0)
  let y-position_current (0)
  let x-position_final (0)
  let y-position_final (0)

  let wall_count (0)
  let number_of_walls (0)

  let horizontal_x_list_start_points []
  let horizontal_y_list_start_points []

  let horizontal_x_list_end_points   []
  let horizontal_y_list_end_points   []

  if (maze_type = "Simple")
  [
    set horizontal_x_list_start_points [16 17 16 17 24 25 24 25 09 09 25 25 09 09 25 25]
    set horizontal_y_list_start_points [09 09 25 25 09 09 25 25 16 17 16 17 24 25 24 25]

    set horizontal_x_list_end_points   [16 17 16 17 24 25 24 25 16 16 32 32 16 16 32 32]
    set horizontal_y_list_end_points   [16 16 32 32 16 16 32 32 16 17 16 17 24 25 24 25]
  ]

  if (maze_type = "Complex")
  [
    set horizontal_x_list_start_points [04 20 20 04 24 04 16 36 08 20 08 28 08 28 24 12 12 36 04 16 28 32 08]
    set horizontal_y_list_start_points [04 04 04 08 08 08 08 08 12 12 16 16 16 16 20 24 24 24 32 32 32 32 36]

    set horizontal_x_list_end_points [16 36 20 16 36 04 16 36 16 32 24 32 08 28 24 20 12 36 12 24 32 32 32]
    set horizontal_y_list_end_points [04 04 12 08 08 32 12 20 12 12 16 16 28 32 32 24 32 36 32 32 32 36 36]
  ]

  set number_of_walls (length horizontal_x_list_start_points)

  while [number_of_walls > 0]
  [
    set x-position_current (item wall_count horizontal_x_list_start_points)
    set y-position_current (item wall_count horizontal_y_list_start_points)
    set x-position_final (item wall_count horizontal_x_list_end_points)
    set y-position_final (item wall_count horizontal_y_list_end_points)

    ifelse (y-position_current = y-position_final) ; horizontal line
    [
      while [x-position_current <= x-position_final]
      [
        ask patch x-position_current y-position_current
        [
          set pcolor BLUE
          set environment_status -10
        ]
        set x-position_current (x-position_current + 1)

      ]
      set number_of_walls (number_of_walls - 1)
      set wall_count (wall_count + 1)
    ]
    [                                              ; vertical line
       while [y-position_current <= y-position_final]
      [
        ask patch x-position_current y-position_current
        [
          set pcolor BLUE
          set environment_status -10
        ]
        set y-position_current (y-position_current + 1)

      ]
      set number_of_walls (number_of_walls - 1)
      set wall_count (wall_count + 1)
    ]
  ]

end

;; this procedure checks the coordinates and makes the entities
;; reflect according to the law that the angle of reflection is
;; equal to the angle of incidence
to check_wall_collision [check_distance]

  ; if not about to hit a wall (blue patch)
  ; no further checks required
  set check_distance (check_distance + 0.01)

  if ([pcolor] of patch-ahead check_distance != BLUE) [stop]

  if (collision_actions = "Random New Heading")
  [
    set heading (random-float 360)
    if ([pcolor] of patch-ahead check_distance = BLUE)
    [
      check_wall_collision (check_distance) ; continue until suitable heading is found
    ]
  ]

  if (collision_actions = "Reflect Off")
  [
    ifelse ((heading = 45) or (heading = 135) or (heading = 225) or (heading = 315))
    [
      set heading (heading + 180)
    ]
    [
      set heading (- heading)
      if ([pcolor] of patch-ahead check_distance = BLUE)
      [
        set heading (heading + 180)
      ]
      if ([pcolor] of patch-ahead check_distance = BLUE) ; incase gets stuck in a corner!
      [
        set heading (heading + 180)
        set heading (- heading)
        set heading (heading + 180)
      ]
    ]
  ]
end

to draw_boundaries
  ; draw left and right walls
  ask patches with [pxcor = max-pxcor]
    [
      set pcolor BLUE
      set environment_status -10
    ]
  ask patches with [pxcor = min-pxcor]
    [
      set pcolor BLUE
      set environment_status -10
    ]
  ; draw top and bottom walls
  ask patches with [pycor = max-pycor]
    [
      set pcolor BLUE
      set environment_status -10
    ]
  ask patches with [pycor = min-pycor]
    [
      set pcolor BLUE
      set environment_status -10
    ]
end


to randomly_set_target_to_search_for

    set searching_for_target_type (random 2) ; i.e. set to 0 or 1

    if (searching_for_target_type = 0) ; searching for nest
    [
      set color YELLOW
    ]
    if (searching_for_target_type = 1) ; searching for food
    [
      set color BLUE
    ]
end

to randomly_position_entity
    set xcor random-xcor
    set ycor random-ycor

    if ([pcolor] of patch-here = BLUE)
    [
      randomly_position_entity
    ]

    if ((xcor > (max-pxcor - 1)) or ((xcor < min-pxcor + 1)) or (ycor > (max-pycor - 1)) or ((ycor < min-pycor + 1))) ; Secondary limit check to make sure in bounds
    [
      randomly_position_entity
    ]

    if(any? other turtles-here)
    [
      randomly_position_entity
    ]
end

to-report distance_position_entity

  let proposed_x 5
  let proposed_y 5

  let attempted_placement_count 0

  let re-run TRUE   ; final check for walls and other entities
  while [re-run = TRUE]
  [
    set re-run FALSE ; first check for location in-bounds
    let location_check TRUE
    while [location_check = TRUE]
    [
      if (attempted_placement_count > 500)
      [
        report FALSE
      ]

      set location_check FALSE

      let direction random 359 ; set a random direction between 0 snd 359 degrees

      ifelse (direction < 90) ; 0 to 89 degrees  +x +y
      [
        set proposed_x (targets_x_position + ((starting_seperation * 2) * sin direction))
        set proposed_y (targets_y_position + ((starting_seperation * 2) * cos direction))
      ]
      [
        ifelse (direction < 180) ; 90 to 179 degrees  +x -y
        [
          set proposed_x (targets_x_position + ((starting_seperation * 2) * sin (180 - direction)))
          set proposed_y (targets_y_position - ((starting_seperation * 2) * cos (180 - direction)))
        ]
        [
          ifelse (direction < 270) ; 180 to 269 degrees  -x -y
          [
            set proposed_x (targets_x_position - ((starting_seperation * 2) * sin (direction - 180)))
            set proposed_y (targets_y_position - ((starting_seperation * 2) * cos (direction - 180)))
          ]
          [ ;  270 to 359 degrees   -x +y
            set proposed_x (targets_x_position - ((starting_seperation * 2) * sin (360 - direction)))
            set proposed_y (targets_y_position + ((starting_seperation * 2) * cos (360 - direction)))
          ]
        ]
      ]

      if ((proposed_x > (max-pxcor - 1)) or (proposed_x < (min-pxcor + 1)) or (proposed_y > (max-pycor - 1)) or (proposed_y < (min-pycor + 1))) ; Secondary limit check to make sure in bounds
      [
        set location_check TRUE

        set attempted_placement_count (attempted_placement_count + 1)
      ]
    ]

    set xcor proposed_x
    set ycor proposed_y

    if ([pcolor] of patch-here = BLUE)
    [
      set re-run TRUE
    ]

    if ([environment_status] of patch-here = -10)
    [
      set re-run TRUE
    ]

    if(any? other turtles-here)
    [
      set re-run TRUE
    ]

    if (re-run = TRUE)
    [
      set attempted_placement_count (attempted_placement_count + 1)
    ]
  ]

  report TRUE

end



to place_target [sub_type]
  create-targets 1
  [
    set step_size_scaling ((world-width - 2) / size_of_sides) ; -2 because of boundary. At begining to allow required scaling factors

    set target_type (sub_type) ; Used to identify different targets

    if (sub_type = 0) ; nest
    [
      set color YELLOW
      set shape "flag"
      set size 1
      set xcor (3 * step_size_scaling)
      set ycor (3 * step_size_scaling)
    ]

    if (sub_type = 1) ; food
    [
      set color BLUE
      set shape "flag"
      set size 1
      set xcor (17 * step_size_scaling)
      set ycor (17 * step_size_scaling)
    ]

    if (sub_type = 2) ; centre point
    [
      set color BLUE
      set shape "flag"
      set size 1
      set xcor (10 * step_size_scaling)
      set ycor (10 * step_size_scaling)
    ]

    if (sub_type = 3) ; position randomly
    [
      set color YELLOW
      set shape "flag"
      set size 1
      randomly_position_entity
    ]

    if (sub_type = 4)
    [
      set color YELLOW
      set shape "flag"
      set size 1
      set xcor (16.5 * step_size_scaling)
      set ycor (16.5 * step_size_scaling)
      set target_type 0
    ]

    set comms_range (comms_range_target * step_size_scaling)
    set target_sequence_number (0)

    set targets_x_position xcor
    set targets_y_position ycor

    set speed (0)

    if (halo_visable = TRUE)
    [
      make-halo
    ]

  ]
end

to-report place_searcher [sub_type]

  let successful TRUE

  create-searchers (number-of-searchers)
  [
    let positioned TRUE
    set step_size_scaling ((world-width - 2) / size_of_sides) ; -2 because of boundary. At begining to allow required scaling factors
    set size 1

    if (sub_type = -1)
    [
      randomly_set_target_to_search_for
      randomly_position_entity
    ]
    ifelse (sub_type = 2)
    [
      set color GREEN
      set shape "person"
      set size 1
      set searching_for_target_type 0
      set positioned distance_position_entity
      if (positioned = FALSE)
      [
        set successful FALSE
      ]
    ]
    [
      set color GREEN
      set shape "person"
      set size 1
      set searching_for_target_type 0
      randomly_position_entity
    ]

    set received_sequence_number_target_type_0 (0)
    set received_distance_to_target_type_0 (1000)

    set own_distance_travelled (0)

    set estimate_distance_to_target_0 (1000) ; larger than the area
    set new_estimate_distance_to_target_0 (1000)

    set estimate_distance_to_target_1 (1000)
    set new_estimate_distance_to_target_1 (1000)

    set distance_to_best_neighbour (0) ; distance of A relative to S - Set to 0 to allow searcher mode to work

    set comms_range (comms_range_searcher * step_size_scaling)
    set speed (0.15 * step_size_scaling)

    pendown

  ]

  ifelse (successful = TRUE)
  [
    report TRUE ; Sucessfully reached end of call
  ]
  [
    report FALSE ; Failed due to position of target
  ]

end

to place_independents [sub_type]

  create-independents (number_of_independents); to allow 1 for experiment - count entities)   ; subtract count entities to allow multiple trgets or searchers
  [
    set step_size_scaling ((world-width - 2) / size_of_sides) ; -2 because of boundary. At begining to allow required scaling factors
    set color WHITE
    set size 1

    randomly_position_entity

    set received_sequence_number_target_type_0 (0)
    set received_distance_to_target_type_0 (1000)
    set received_sequence_number_target_type_1 (0)
    set received_distance_to_target_type_1 (1000)

    set comms_range (comms_range_other * step_size_scaling)
    set speed (0.15 * step_size_scaling)
    set own_distance_to_move ((random-exponential 10) * speed) ; set for 10 seconds - from paper section 3.2

  ]
end

to place_malicious_entities [sub_type] ; sub-type: 0 - Fixed Jammer, 1 - Mobile Jammer, 2 - Masquerade, 3 - Jammer and Masquerade (Mobile)


    let malicious_x_points []
    let malicious_y_points []
    let malicious_count 0
    if size_of_malicious_swarm = "small"
    [
      set malicious_x_points [04 10 16 04 16 04 10 16]
      set malicious_y_points [04 04 04 10 10 16 16 16]
    ]
    if size_of_malicious_swarm = "medium"
    [
      set malicious_x_points [04 06 10 14 16 04 06 10 14 16 04 06 10 14 16 04 06 14 16 04 06 10 14 16 04 06 10 14 16 04 06 10 14 16]
      set malicious_y_points [04 04 04 04 04 04 04 06 06 06 06 06 06 06 10 10 10 10 10 10 14 14 14 14 14 14 14 16 16 16 16 16 16 16]
    ]
    if size_of_malicious_swarm = "large"
    [
      set malicious_x_points [02 04 06 08 10 12 14 16 18 02 04 06 10 14 16 18 02 04 06 10 14 16 18 02 18 02 04 06 14 16 18 02 18 02 04 06 10 14 16 18 02 04 06 10 14 16 18 02 04 06 08 10 12 14 16 18]
      set malicious_y_points [02 02 02 02 02 02 02 02 02 04 04 04 04 04 04 04 06 06 06 06 06 06 06 08 08 10 10 10 10 10 10 12 12 14 14 14 14 14 14 14 16 16 16 16 16 16 16 18 18 18 18 18 18 18 18 18]
    ]

    set number-of-malicious-entities (length malicious_x_points)

    let number_of_mal_entities number-of-malicious-entities

    set malicious_count 0

    while [number_of_mal_entities > 0]
    [
      create-malicious_entities 1
      [
        set step_size_scaling ((world-width - 2) / size_of_sides) ; -2 because of boundary. At begining to allow required scaling factors

        set jammer TRUE
        set color RED
        set shape "x"
        set size 1

        set xcor ((item malicious_count malicious_x_points) * step_size_scaling)
        set ycor ((item malicious_count malicious_y_points) * step_size_scaling)
      ]

      set number_of_mal_entities (number_of_mal_entities - 1)
      set malicious_count (malicious_count + 1)
    ]

end

to place_detectors [sub_type] ; 0 - randomly place, 1 - place in centre

  create-detectors (number_of_detectors); to allow 1 for experiment - count entities)   ; subtract count entities to allow multiple trgets or searchers
  [
    set step_size_scaling ((world-width - 2) / size_of_sides) ; -2 because of boundary. At begining to allow required scaling factors
    set color BLUE
    set size 1

    set target_count 0

    if (sub_type = 0)
    [
      randomly_position_entity
    ]

    if (sub_type = 1)
    [
      set xcor (10 * step_size_scaling)
      set ycor (10 * step_size_scaling)
    ]

    set received_sequence_number_target_type_0 (0)
    set received_distance_to_target_type_0 (1000)
    set received_sequence_number_target_type_1 (0)
    set received_distance_to_target_type_1 (1000)

    set comms_range (comms_range_detector * step_size_scaling)
    set speed (0.15 * step_size_scaling)
    set own_distance_to_move ((random-exponential 10) * speed) ; set for 10 seconds - from paper section 3.2

    set visable_targets []

    set suspicious_activity FALSE

  ]
end

to make-halo  ;; runner procedure
  ;; when you use HATCH, the new turtle inherits the
  ;; characteristics of the parent.  so the halo will
  ;; be the same color as the turtle it encircles (unless
  ;; you add code to change it
  hatch-halos 1
  [ set size (starting_seperation * 2 * step_size_scaling) ; *2 to make size from diameter to radius
    ;; Use an RGB color to make halo three fourths transparent
    set color lput 64 extract-rgb color
    ;; set thickness of halo to half a patch
    __set-line-thickness 0.5
    ;; We create an invisible directed link from the runner
    ;; to the halo.  Using tie means that whenever the
    ;; runner moves, the halo moves with it.
    create-link-from myself
    [ tie
      hide-link ] ]
end


to-report bearing-of-neighbour [nearest-neighbour]
;; "towards myself" gives us the heading from the other entity to me, but we want the heading
;; from this entity to the other entity, so add 180.  Also see safe-atan
  report safe-atan [sin (towards myself + 180)] of nearest-neighbour
                   [cos (towards myself + 180)] of nearest-neighbour
end

;; Avoid atan 0 0 problem. Essential for Behavior Space
to-report safe-atan [x y] report ifelse-value (x = 0 and y = 0) [0][atan x y] end
@#$#@#$#@
GRAPHICS-WINDOW
210
10
640
461
-1
-1
10.0
1
10
1
1
1
0
0
0
1
0
41
0
41
0
0
1
ticks
30.0

BUTTON
6
64
114
97
Go Single Run
go_single
T
1
T
OBSERVER
NIL
NIL
NIL
NIL
1

BUTTON
8
105
120
138
Go Experiment
go_exp
NIL
1
T
OBSERVER
NIL
NIL
NIL
NIL
1

BUTTON
7
10
71
43
Setup
setup
NIL
1
T
OBSERVER
NIL
NIL
NIL
NIL
1

CHOOSER
669
19
807
64
maze_type
maze_type
"None" "Simple" "Complex"
0

CHOOSER
672
182
811
227
collision_actions
collision_actions
"Reflect Off" "Random New Heading"
0

SLIDER
670
76
842
109
size_of_sides
size_of_sides
10
30
20
1
1
NIL
HORIZONTAL

SLIDER
13
270
179
303
number-of-searchers
number-of-searchers
0
100
0
1
1
NIL
HORIZONTAL

CHOOSER
670
125
816
170
searcher_mode
searcher_mode
"Wait for message" "Move Randomly"
1

INPUTBOX
7
477
226
537
File_Name
No_Maze_Small - 2 Only
1
0
String

SLIDER
671
236
843
269
comms_range_searcher
comms_range_searcher
1
10
3
1
1
NIL
HORIZONTAL

SLIDER
671
281
843
314
comms_range_target
comms_range_target
1
10
3
1
1
NIL
HORIZONTAL

SLIDER
672
328
844
361
comms_range_other
comms_range_other
1
10
3
1
1
NIL
HORIZONTAL

SLIDER
10
367
178
400
number-of-malicious-entities
number-of-malicious-entities
0
100
8
1
1
NIL
HORIZONTAL

SLIDER
671
374
842
407
comms_range_malicious
comms_range_malicious
1
10
3
1
1
NIL
HORIZONTAL

SLIDER
879
322
1068
355
jamming_range_malicious
jamming_range_malicious
0
10
3
1
1
NIL
HORIZONTAL

SLIDER
879
281
1051
314
jamming_period
jamming_period
1
10
5
1
1
NIL
HORIZONTAL

SLIDER
878
362
1050
395
chance_of_jamming
chance_of_jamming
0
50
6
1
1
NIL
HORIZONTAL

CHOOSER
879
230
1017
275
jamming_attack
jamming_attack
"No Attack" "Fixed Jammers" "Mobile Jammers"
0

SLIDER
11
317
179
350
number_of_independents
number_of_independents
0
100
90
1
1
NIL
HORIZONTAL

CHOOSER
879
406
1052
451
jamming_attackers_visable
jamming_attackers_visable
"TRUE" "FALSE"
0

SLIDER
11
222
182
255
starting_seperation
starting_seperation
5
15
15
1
1
NIL
HORIZONTAL

INPUTBOX
9
150
111
210
number_of_rounds
100
1
0
Number

SLIDER
6
417
178
450
number_of_detectors
number_of_detectors
0
10
2
1
1
NIL
HORIZONTAL

SLIDER
671
421
842
454
comms_range_detector
comms_range_detector
1
10
3
1
1
NIL
HORIZONTAL

SWITCH
673
464
797
497
halo_visable
halo_visable
1
1
-1000

SLIDER
289
498
484
531
detection_accuracy_range
detection_accuracy_range
0.1
1
0.1
0.1
1
NIL
HORIZONTAL

CHOOSER
504
496
642
541
attack_to_detect
attack_to_detect
"none" "stationary" "straight_line"
1

SLIDER
290
540
484
573
detection_accuracy_angle
detection_accuracy_angle
1
10
1
1
1
NIL
HORIZONTAL

MONITOR
933
35
1007
80
NIL
good_find
17
1
11

MONITOR
934
95
1029
140
NIL
false_positives
17
1
11

MONITOR
933
156
1034
201
NIL
false_negatives
17
1
11

CHOOSER
514
555
676
600
size_of_malicious_swarm
size_of_malicious_swarm
"small" "medium" "large"
0

@#$#@#$#@
## WHAT IS IT?

(a general understanding of what the model is trying to show or explain)

## HOW IT WORKS

(what rules the agents use to create the overall behavior of the model)

## HOW TO USE IT

(how to use the model, including a description of each of the items in the Interface tab)

## THINGS TO NOTICE

(suggested things for the user to notice while running the model)

## THINGS TO TRY

(suggested things for the user to try to do (move sliders, switches, etc.) with the model)

## EXTENDING THE MODEL

(suggested things to add or change in the Code tab to make the model more complicated, detailed, accurate, etc.)

## NETLOGO FEATURES

(interesting or unusual features of NetLogo that the model uses, particularly in the Code tab; or where workarounds were needed for missing features)

## RELATED MODELS

(models in the NetLogo Models Library and elsewhere which are of related interest)

## CREDITS AND REFERENCES

(a reference to the model's URL on the web if it has one, as well as any other necessary credits, citations, and links)
@#$#@#$#@
default
true
0
Polygon -7500403 true true 150 5 40 250 150 205 260 250

airplane
true
0
Polygon -7500403 true true 150 0 135 15 120 60 120 105 15 165 15 195 120 180 135 240 105 270 120 285 150 270 180 285 210 270 165 240 180 180 285 195 285 165 180 105 180 60 165 15

arrow
true
0
Polygon -7500403 true true 150 0 0 150 105 150 105 293 195 293 195 150 300 150

box
false
0
Polygon -7500403 true true 150 285 285 225 285 75 150 135
Polygon -7500403 true true 150 135 15 75 150 15 285 75
Polygon -7500403 true true 15 75 15 225 150 285 150 135
Line -16777216 false 150 285 150 135
Line -16777216 false 150 135 15 75
Line -16777216 false 150 135 285 75

bug
true
0
Circle -7500403 true true 96 182 108
Circle -7500403 true true 110 127 80
Circle -7500403 true true 110 75 80
Line -7500403 true 150 100 80 30
Line -7500403 true 150 100 220 30

butterfly
true
0
Polygon -7500403 true true 150 165 209 199 225 225 225 255 195 270 165 255 150 240
Polygon -7500403 true true 150 165 89 198 75 225 75 255 105 270 135 255 150 240
Polygon -7500403 true true 139 148 100 105 55 90 25 90 10 105 10 135 25 180 40 195 85 194 139 163
Polygon -7500403 true true 162 150 200 105 245 90 275 90 290 105 290 135 275 180 260 195 215 195 162 165
Polygon -16777216 true false 150 255 135 225 120 150 135 120 150 105 165 120 180 150 165 225
Circle -16777216 true false 135 90 30
Line -16777216 false 150 105 195 60
Line -16777216 false 150 105 105 60

car
false
0
Polygon -7500403 true true 300 180 279 164 261 144 240 135 226 132 213 106 203 84 185 63 159 50 135 50 75 60 0 150 0 165 0 225 300 225 300 180
Circle -16777216 true false 180 180 90
Circle -16777216 true false 30 180 90
Polygon -16777216 true false 162 80 132 78 134 135 209 135 194 105 189 96 180 89
Circle -7500403 true true 47 195 58
Circle -7500403 true true 195 195 58

circle
false
0
Circle -7500403 true true 0 0 300

circle 2
false
0
Circle -7500403 true true 0 0 300
Circle -16777216 true false 30 30 240

cow
false
0
Polygon -7500403 true true 200 193 197 249 179 249 177 196 166 187 140 189 93 191 78 179 72 211 49 209 48 181 37 149 25 120 25 89 45 72 103 84 179 75 198 76 252 64 272 81 293 103 285 121 255 121 242 118 224 167
Polygon -7500403 true true 73 210 86 251 62 249 48 208
Polygon -7500403 true true 25 114 16 195 9 204 23 213 25 200 39 123

cylinder
false
0
Circle -7500403 true true 0 0 300

dot
false
0
Circle -7500403 true true 90 90 120

face happy
false
0
Circle -7500403 true true 8 8 285
Circle -16777216 true false 60 75 60
Circle -16777216 true false 180 75 60
Polygon -16777216 true false 150 255 90 239 62 213 47 191 67 179 90 203 109 218 150 225 192 218 210 203 227 181 251 194 236 217 212 240

face neutral
false
0
Circle -7500403 true true 8 7 285
Circle -16777216 true false 60 75 60
Circle -16777216 true false 180 75 60
Rectangle -16777216 true false 60 195 240 225

face sad
false
0
Circle -7500403 true true 8 8 285
Circle -16777216 true false 60 75 60
Circle -16777216 true false 180 75 60
Polygon -16777216 true false 150 168 90 184 62 210 47 232 67 244 90 220 109 205 150 198 192 205 210 220 227 242 251 229 236 206 212 183

fish
false
0
Polygon -1 true false 44 131 21 87 15 86 0 120 15 150 0 180 13 214 20 212 45 166
Polygon -1 true false 135 195 119 235 95 218 76 210 46 204 60 165
Polygon -1 true false 75 45 83 77 71 103 86 114 166 78 135 60
Polygon -7500403 true true 30 136 151 77 226 81 280 119 292 146 292 160 287 170 270 195 195 210 151 212 30 166
Circle -16777216 true false 215 106 30

flag
false
0
Rectangle -7500403 true true 60 15 75 300
Polygon -7500403 true true 90 150 270 90 90 30
Line -7500403 true 75 135 90 135
Line -7500403 true 75 45 90 45

flower
false
0
Polygon -10899396 true false 135 120 165 165 180 210 180 240 150 300 165 300 195 240 195 195 165 135
Circle -7500403 true true 85 132 38
Circle -7500403 true true 130 147 38
Circle -7500403 true true 192 85 38
Circle -7500403 true true 85 40 38
Circle -7500403 true true 177 40 38
Circle -7500403 true true 177 132 38
Circle -7500403 true true 70 85 38
Circle -7500403 true true 130 25 38
Circle -7500403 true true 96 51 108
Circle -16777216 true false 113 68 74
Polygon -10899396 true false 189 233 219 188 249 173 279 188 234 218
Polygon -10899396 true false 180 255 150 210 105 210 75 240 135 240

house
false
0
Rectangle -7500403 true true 45 120 255 285
Rectangle -16777216 true false 120 210 180 285
Polygon -7500403 true true 15 120 150 15 285 120
Line -16777216 false 30 120 270 120

leaf
false
0
Polygon -7500403 true true 150 210 135 195 120 210 60 210 30 195 60 180 60 165 15 135 30 120 15 105 40 104 45 90 60 90 90 105 105 120 120 120 105 60 120 60 135 30 150 15 165 30 180 60 195 60 180 120 195 120 210 105 240 90 255 90 263 104 285 105 270 120 285 135 240 165 240 180 270 195 240 210 180 210 165 195
Polygon -7500403 true true 135 195 135 240 120 255 105 255 105 285 135 285 165 240 165 195

line
true
0
Line -7500403 true 150 0 150 300

line half
true
0
Line -7500403 true 150 0 150 150

pentagon
false
0
Polygon -7500403 true true 150 15 15 120 60 285 240 285 285 120

person
false
0
Circle -7500403 true true 110 5 80
Polygon -7500403 true true 105 90 120 195 90 285 105 300 135 300 150 225 165 300 195 300 210 285 180 195 195 90
Rectangle -7500403 true true 127 79 172 94
Polygon -7500403 true true 195 90 240 150 225 180 165 105
Polygon -7500403 true true 105 90 60 150 75 180 135 105

plant
false
0
Rectangle -7500403 true true 135 90 165 300
Polygon -7500403 true true 135 255 90 210 45 195 75 255 135 285
Polygon -7500403 true true 165 255 210 210 255 195 225 255 165 285
Polygon -7500403 true true 135 180 90 135 45 120 75 180 135 210
Polygon -7500403 true true 165 180 165 210 225 180 255 120 210 135
Polygon -7500403 true true 135 105 90 60 45 45 75 105 135 135
Polygon -7500403 true true 165 105 165 135 225 105 255 45 210 60
Polygon -7500403 true true 135 90 120 45 150 15 180 45 165 90

sheep
false
15
Circle -1 true true 203 65 88
Circle -1 true true 70 65 162
Circle -1 true true 150 105 120
Polygon -7500403 true false 218 120 240 165 255 165 278 120
Circle -7500403 true false 214 72 67
Rectangle -1 true true 164 223 179 298
Polygon -1 true true 45 285 30 285 30 240 15 195 45 210
Circle -1 true true 3 83 150
Rectangle -1 true true 65 221 80 296
Polygon -1 true true 195 285 210 285 210 240 240 210 195 210
Polygon -7500403 true false 276 85 285 105 302 99 294 83
Polygon -7500403 true false 219 85 210 105 193 99 201 83

square
false
0
Rectangle -7500403 true true 30 30 270 270

square 2
false
0
Rectangle -7500403 true true 30 30 270 270
Rectangle -16777216 true false 60 60 240 240

star
false
0
Polygon -7500403 true true 151 1 185 108 298 108 207 175 242 282 151 216 59 282 94 175 3 108 116 108

target
false
0
Circle -7500403 true true 0 0 300
Circle -16777216 true false 30 30 240
Circle -7500403 true true 60 60 180
Circle -16777216 true false 90 90 120
Circle -7500403 true true 120 120 60

thin ring
true
0
Circle -7500403 false true -1 -1 301

tree
false
0
Circle -7500403 true true 118 3 94
Rectangle -6459832 true false 120 195 180 300
Circle -7500403 true true 65 21 108
Circle -7500403 true true 116 41 127
Circle -7500403 true true 45 90 120
Circle -7500403 true true 104 74 152

triangle
false
0
Polygon -7500403 true true 150 30 15 255 285 255

triangle 2
false
0
Polygon -7500403 true true 150 30 15 255 285 255
Polygon -16777216 true false 151 99 225 223 75 224

truck
false
0
Rectangle -7500403 true true 4 45 195 187
Polygon -7500403 true true 296 193 296 150 259 134 244 104 208 104 207 194
Rectangle -1 true false 195 60 195 105
Polygon -16777216 true false 238 112 252 141 219 141 218 112
Circle -16777216 true false 234 174 42
Rectangle -7500403 true true 181 185 214 194
Circle -16777216 true false 144 174 42
Circle -16777216 true false 24 174 42
Circle -7500403 false true 24 174 42
Circle -7500403 false true 144 174 42
Circle -7500403 false true 234 174 42

turtle
true
0
Polygon -10899396 true false 215 204 240 233 246 254 228 266 215 252 193 210
Polygon -10899396 true false 195 90 225 75 245 75 260 89 269 108 261 124 240 105 225 105 210 105
Polygon -10899396 true false 105 90 75 75 55 75 40 89 31 108 39 124 60 105 75 105 90 105
Polygon -10899396 true false 132 85 134 64 107 51 108 17 150 2 192 18 192 52 169 65 172 87
Polygon -10899396 true false 85 204 60 233 54 254 72 266 85 252 107 210
Polygon -7500403 true true 119 75 179 75 209 101 224 135 220 225 175 261 128 261 81 224 74 135 88 99

wheel
false
0
Circle -7500403 true true 3 3 294
Circle -16777216 true false 30 30 240
Line -7500403 true 150 285 150 15
Line -7500403 true 15 150 285 150
Circle -7500403 true true 120 120 60
Line -7500403 true 216 40 79 269
Line -7500403 true 40 84 269 221
Line -7500403 true 40 216 269 79
Line -7500403 true 84 40 221 269

wolf
false
0
Polygon -16777216 true false 253 133 245 131 245 133
Polygon -7500403 true true 2 194 13 197 30 191 38 193 38 205 20 226 20 257 27 265 38 266 40 260 31 253 31 230 60 206 68 198 75 209 66 228 65 243 82 261 84 268 100 267 103 261 77 239 79 231 100 207 98 196 119 201 143 202 160 195 166 210 172 213 173 238 167 251 160 248 154 265 169 264 178 247 186 240 198 260 200 271 217 271 219 262 207 258 195 230 192 198 210 184 227 164 242 144 259 145 284 151 277 141 293 140 299 134 297 127 273 119 270 105
Polygon -7500403 true true -1 195 14 180 36 166 40 153 53 140 82 131 134 133 159 126 188 115 227 108 236 102 238 98 268 86 269 92 281 87 269 103 269 113

x
false
0
Polygon -7500403 true true 270 75 225 30 30 225 75 270
Polygon -7500403 true true 30 75 75 30 270 225 225 270

@#$#@#$#@
NetLogo 5.3.1
@#$#@#$#@
@#$#@#$#@
@#$#@#$#@
@#$#@#$#@
@#$#@#$#@
default
0.0
-0.2 0 0.0 1.0
0.0 1 1.0 0.0
0.2 0 0.0 1.0
link direction
true
0
Line -7500403 true 150 150 90 180
Line -7500403 true 150 150 210 180

@#$#@#$#@
0
@#$#@#$#@
