/*
Copyright 2025 Guided Traffic.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"fmt"
	"strings"
	"time"
)

// validDays maps day names to time.Weekday values
var validDays = map[string]time.Weekday{
	"sunday":    time.Sunday,
	"monday":    time.Monday,
	"tuesday":   time.Tuesday,
	"wednesday": time.Wednesday,
	"thursday":  time.Thursday,
	"friday":    time.Friday,
	"saturday":  time.Saturday,
}

// Validate validates the MaintenanceWindowsConfig
func (m *MaintenanceWindowsConfig) Validate() error {
	if len(m.Windows) == 0 {
		return fmt.Errorf("at least one maintenance window must be defined when enabled")
	}

	for i, window := range m.Windows {
		if err := window.Validate(); err != nil {
			if window.Name != "" {
				return fmt.Errorf("window '%s': %w", window.Name, err)
			}
			return fmt.Errorf("window[%d]: %w", i, err)
		}
	}

	return nil
}

// Validate validates a single MaintenanceWindow
func (w *MaintenanceWindow) Validate() error {
	// Validate name (optional but recommended)
	// No validation needed, empty name is allowed

	// Validate days
	if len(w.Days) == 0 {
		return fmt.Errorf("at least one day must be specified")
	}

	for _, day := range w.Days {
		if _, err := ParseDay(day); err != nil {
			return err
		}
	}

	// Validate startTime
	startHour, startMinute, err := ParseTime(w.StartTime)
	if err != nil {
		return fmt.Errorf("invalid startTime: %w", err)
	}

	// Validate endTime
	endHour, endMinute, err := ParseTime(w.EndTime)
	if err != nil {
		return fmt.Errorf("invalid endTime: %w", err)
	}

	// Validate that endTime > startTime (no overnight windows)
	startMinutes := startHour*60 + startMinute
	endMinutes := endHour*60 + endMinute
	if endMinutes <= startMinutes {
		return fmt.Errorf("endTime (%s) must be after startTime (%s)", w.EndTime, w.StartTime)
	}

	// Validate timezone
	if w.Timezone == "" {
		return fmt.Errorf("timezone must be specified")
	}

	if _, err := time.LoadLocation(w.Timezone); err != nil {
		return fmt.Errorf("invalid timezone '%s': %w", w.Timezone, err)
	}

	return nil
}

// ParseDay parses a day name string to time.Weekday
func ParseDay(day string) (time.Weekday, error) {
	normalized := strings.ToLower(strings.TrimSpace(day))
	if weekday, ok := validDays[normalized]; ok {
		return weekday, nil
	}
	return time.Sunday, fmt.Errorf("invalid day: '%s', must be one of: sunday, monday, tuesday, wednesday, thursday, friday, saturday", day)
}

// ParseTime parses a time string in HH:MM format
func ParseTime(timeStr string) (hour, minute int, err error) {
	if timeStr == "" {
		return 0, 0, fmt.Errorf("time cannot be empty")
	}

	parts := strings.Split(timeStr, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid time format '%s', expected HH:MM", timeStr)
	}

	if _, err := fmt.Sscanf(parts[0], "%d", &hour); err != nil {
		return 0, 0, fmt.Errorf("invalid hour in '%s': %w", timeStr, err)
	}

	if _, err := fmt.Sscanf(parts[1], "%d", &minute); err != nil {
		return 0, 0, fmt.Errorf("invalid minute in '%s': %w", timeStr, err)
	}

	if hour < 0 || hour > 23 {
		return 0, 0, fmt.Errorf("hour must be between 0 and 23, got %d", hour)
	}

	if minute < 0 || minute > 59 {
		return 0, 0, fmt.Errorf("minute must be between 0 and 59, got %d", minute)
	}

	return hour, minute, nil
}

// IsInWindow checks if the given time falls within this maintenance window
func (w *MaintenanceWindow) IsInWindow(t time.Time) bool {
	// Load the timezone
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		// This should not happen if Validate() was called
		return false
	}

	// Convert to the window's timezone
	localTime := t.In(loc)

	// Check if the day matches
	currentDay := localTime.Weekday()
	dayMatches := false
	for _, day := range w.Days {
		weekday, err := ParseDay(day)
		if err != nil {
			continue
		}
		if weekday == currentDay {
			dayMatches = true
			break
		}
	}

	if !dayMatches {
		return false
	}

	// Parse start and end times
	startHour, startMinute, _ := ParseTime(w.StartTime)
	endHour, endMinute, _ := ParseTime(w.EndTime)

	// Convert current time to minutes since midnight
	currentMinutes := localTime.Hour()*60 + localTime.Minute()
	startMinutes := startHour*60 + startMinute
	endMinutes := endHour*60 + endMinute

	// Check if current time is within the window
	return currentMinutes >= startMinutes && currentMinutes < endMinutes
}

// IsInAnyWindow checks if the given time falls within any of the maintenance windows
func (m *MaintenanceWindowsConfig) IsInAnyWindow(t time.Time) bool {
	if !m.Enabled {
		// If maintenance windows are disabled, always allow rotation
		return true
	}

	for i := range m.Windows {
		if m.Windows[i].IsInWindow(t) {
			return true
		}
	}

	return false
}

// GetActiveWindow returns the active maintenance window for the given time, or nil if none is active
func (m *MaintenanceWindowsConfig) GetActiveWindow(t time.Time) *MaintenanceWindow {
	if !m.Enabled {
		return nil
	}

	for i := range m.Windows {
		if m.Windows[i].IsInWindow(t) {
			return &m.Windows[i]
		}
	}

	return nil
}

// NextWindowStart calculates the next maintenance window start time from the given time
func (m *MaintenanceWindowsConfig) NextWindowStart(t time.Time) time.Time {
	if !m.Enabled || len(m.Windows) == 0 {
		// If disabled, return zero time
		return time.Time{}
	}

	var earliest time.Time

	for i := range m.Windows {
		next := m.Windows[i].NextStart(t)
		if earliest.IsZero() || next.Before(earliest) {
			earliest = next
		}
	}

	return earliest
}

// NextStart calculates the next start time for this window from the given time
func (w *MaintenanceWindow) NextStart(t time.Time) time.Time {
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		return time.Time{}
	}

	localTime := t.In(loc)
	startHour, startMinute, _ := ParseTime(w.StartTime)
	endHour, endMinute, _ := ParseTime(w.EndTime)

	// Parse the days
	var windowDays []time.Weekday
	for _, day := range w.Days {
		weekday, err := ParseDay(day)
		if err != nil {
			continue
		}
		windowDays = append(windowDays, weekday)
	}

	if len(windowDays) == 0 {
		return time.Time{}
	}

	// Check today first
	currentDay := localTime.Weekday()
	currentMinutes := localTime.Hour()*60 + localTime.Minute()
	startMinutes := startHour*60 + startMinute
	endMinutes := endHour*60 + endMinute

	// If today is a valid day and we're before the window end
	for _, day := range windowDays {
		if day == currentDay {
			// If we're before the window starts today
			if currentMinutes < startMinutes {
				return time.Date(localTime.Year(), localTime.Month(), localTime.Day(),
					startHour, startMinute, 0, 0, loc)
			}
			// If we're currently in the window, next start is... now (or we could skip to next occurrence)
			// For requeue purposes, if we're in the window, we don't need to wait
			if currentMinutes >= startMinutes && currentMinutes < endMinutes {
				return time.Date(localTime.Year(), localTime.Month(), localTime.Day(),
					startHour, startMinute, 0, 0, loc)
			}
		}
	}

	// Find the next valid day
	for daysAhead := 1; daysAhead <= 7; daysAhead++ {
		futureDay := (currentDay + time.Weekday(daysAhead)) % 7
		for _, day := range windowDays {
			if day == futureDay {
				futureDate := localTime.AddDate(0, 0, daysAhead)
				return time.Date(futureDate.Year(), futureDate.Month(), futureDate.Day(),
					startHour, startMinute, 0, 0, loc)
			}
		}
	}

	// Should never reach here if windowDays is not empty
	return time.Time{}
}

// DurationUntilNextWindow calculates the duration until the next maintenance window starts
func (m *MaintenanceWindowsConfig) DurationUntilNextWindow(t time.Time) time.Duration {
	if !m.Enabled {
		return 0
	}

	// If we're already in a window, return 0
	if m.IsInAnyWindow(t) {
		return 0
	}

	next := m.NextWindowStart(t)
	if next.IsZero() {
		return 0
	}

	return next.Sub(t)
}
