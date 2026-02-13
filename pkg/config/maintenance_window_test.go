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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDay(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    time.Weekday
		expectError bool
	}{
		{"sunday lowercase", "sunday", time.Sunday, false},
		{"monday lowercase", "monday", time.Monday, false},
		{"tuesday lowercase", "tuesday", time.Tuesday, false},
		{"wednesday lowercase", "wednesday", time.Wednesday, false},
		{"thursday lowercase", "thursday", time.Thursday, false},
		{"friday lowercase", "friday", time.Friday, false},
		{"saturday lowercase", "saturday", time.Saturday, false},
		{"Sunday uppercase", "Sunday", time.Sunday, false},
		{"MONDAY uppercase", "MONDAY", time.Monday, false},
		{"MiXeD case", "TuEsDaY", time.Tuesday, false},
		{"with spaces", "  wednesday  ", time.Wednesday, false},
		{"invalid day", "funday", time.Sunday, true},
		{"empty string", "", time.Sunday, true},
		{"number", "1", time.Sunday, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseDay(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedHour   int
		expectedMinute int
		expectError    bool
	}{
		{"valid time 03:00", "03:00", 3, 0, false},
		{"valid time 23:59", "23:59", 23, 59, false},
		{"valid time 00:00", "00:00", 0, 0, false},
		{"valid time 12:30", "12:30", 12, 30, false},
		{"invalid hour 24:00", "24:00", 0, 0, true},
		{"invalid hour 25:00", "25:00", 0, 0, true},
		{"invalid minute 12:60", "12:60", 0, 0, true},
		{"negative hour -1:00", "-1:00", 0, 0, true},
		{"empty string", "", 0, 0, true},
		{"missing minute", "12", 0, 0, true},
		{"wrong separator", "12-30", 0, 0, true},
		{"invalid format", "12:30:45", 0, 0, true},
		{"non-numeric hour", "ab:30", 0, 0, true},
		{"non-numeric minute", "12:cd", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hour, minute, err := ParseTime(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedHour, hour)
				assert.Equal(t, tt.expectedMinute, minute)
			}
		})
	}
}

func TestMaintenanceWindowValidate(t *testing.T) {
	tests := []struct {
		name        string
		window      MaintenanceWindow
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid window",
			window: MaintenanceWindow{
				Name:      "weekend-night",
				Days:      []string{"saturday", "sunday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			expectError: false,
		},
		{
			name: "valid window without name",
			window: MaintenanceWindow{
				Days:      []string{"monday"},
				StartTime: "02:00",
				EndTime:   "04:00",
				Timezone:  "UTC",
			},
			expectError: false,
		},
		{
			name: "empty days",
			window: MaintenanceWindow{
				Name:      "test",
				Days:      []string{},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "UTC",
			},
			expectError: true,
			errorMsg:    "at least one day must be specified",
		},
		{
			name: "invalid day",
			window: MaintenanceWindow{
				Name:      "test",
				Days:      []string{"funday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "UTC",
			},
			expectError: true,
			errorMsg:    "invalid day",
		},
		{
			name: "invalid startTime",
			window: MaintenanceWindow{
				Name:      "test",
				Days:      []string{"saturday"},
				StartTime: "25:00",
				EndTime:   "05:00",
				Timezone:  "UTC",
			},
			expectError: true,
			errorMsg:    "invalid startTime",
		},
		{
			name: "invalid endTime",
			window: MaintenanceWindow{
				Name:      "test",
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "invalid",
				Timezone:  "UTC",
			},
			expectError: true,
			errorMsg:    "invalid endTime",
		},
		{
			name: "endTime before startTime",
			window: MaintenanceWindow{
				Name:      "test",
				Days:      []string{"saturday"},
				StartTime: "05:00",
				EndTime:   "03:00",
				Timezone:  "UTC",
			},
			expectError: true,
			errorMsg:    "endTime (03:00) must be after startTime (05:00)",
		},
		{
			name: "endTime equals startTime",
			window: MaintenanceWindow{
				Name:      "test",
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "03:00",
				Timezone:  "UTC",
			},
			expectError: true,
			errorMsg:    "endTime (03:00) must be after startTime (03:00)",
		},
		{
			name: "empty timezone",
			window: MaintenanceWindow{
				Name:      "test",
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "",
			},
			expectError: true,
			errorMsg:    "timezone must be specified",
		},
		{
			name: "invalid timezone",
			window: MaintenanceWindow{
				Name:      "test",
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Invalid/Timezone",
			},
			expectError: true,
			errorMsg:    "invalid timezone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.window.Validate()
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMaintenanceWindowsConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      MaintenanceWindowsConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with one window",
			config: MaintenanceWindowsConfig{
				Enabled: true,
				Windows: []MaintenanceWindow{
					{
						Name:      "weekend",
						Days:      []string{"saturday", "sunday"},
						StartTime: "03:00",
						EndTime:   "05:00",
						Timezone:  "UTC",
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid config with multiple windows",
			config: MaintenanceWindowsConfig{
				Enabled: true,
				Windows: []MaintenanceWindow{
					{
						Name:      "weekend",
						Days:      []string{"saturday", "sunday"},
						StartTime: "03:00",
						EndTime:   "05:00",
						Timezone:  "Europe/Berlin",
					},
					{
						Name:      "weekday",
						Days:      []string{"wednesday"},
						StartTime: "02:00",
						EndTime:   "04:00",
						Timezone:  "Europe/Berlin",
					},
				},
			},
			expectError: false,
		},
		{
			name: "empty windows when enabled",
			config: MaintenanceWindowsConfig{
				Enabled: true,
				Windows: []MaintenanceWindow{},
			},
			expectError: true,
			errorMsg:    "at least one maintenance window must be defined",
		},
		{
			name: "invalid window in list",
			config: MaintenanceWindowsConfig{
				Enabled: true,
				Windows: []MaintenanceWindow{
					{
						Name:      "invalid",
						Days:      []string{"saturday"},
						StartTime: "05:00",
						EndTime:   "03:00", // invalid: end before start
						Timezone:  "UTC",
					},
				},
			},
			expectError: true,
			errorMsg:    "window 'invalid'",
		},
		{
			name: "invalid window without name shows index",
			config: MaintenanceWindowsConfig{
				Enabled: true,
				Windows: []MaintenanceWindow{
					{
						Days:      []string{"saturday"},
						StartTime: "05:00",
						EndTime:   "03:00", // invalid: end before start
						Timezone:  "UTC",
					},
				},
			},
			expectError: true,
			errorMsg:    "window[0]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMaintenanceWindowIsInWindow(t *testing.T) {
	berlinLoc, _ := time.LoadLocation("Europe/Berlin")
	utcLoc := time.UTC

	tests := []struct {
		name     string
		window   MaintenanceWindow
		testTime time.Time
		expected bool
	}{
		{
			name: "inside window - Saturday 04:00 Berlin",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			// Saturday, 4:00 AM Berlin time
			testTime: time.Date(2026, 2, 7, 4, 0, 0, 0, berlinLoc),
			expected: true,
		},
		{
			name: "at start time - exactly 03:00",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			testTime: time.Date(2026, 2, 7, 3, 0, 0, 0, berlinLoc),
			expected: true,
		},
		{
			name: "at end time - exactly 05:00 (exclusive)",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			testTime: time.Date(2026, 2, 7, 5, 0, 0, 0, berlinLoc),
			expected: false,
		},
		{
			name: "before window - Saturday 02:59",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			testTime: time.Date(2026, 2, 7, 2, 59, 0, 0, berlinLoc),
			expected: false,
		},
		{
			name: "after window - Saturday 06:00",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			testTime: time.Date(2026, 2, 7, 6, 0, 0, 0, berlinLoc),
			expected: false,
		},
		{
			name: "wrong day - Friday same time",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			testTime: time.Date(2026, 2, 6, 4, 0, 0, 0, berlinLoc), // Friday
			expected: false,
		},
		{
			name: "multiple days - Saturday",
			window: MaintenanceWindow{
				Days:      []string{"saturday", "sunday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			testTime: time.Date(2026, 2, 7, 4, 0, 0, 0, berlinLoc), // Saturday
			expected: true,
		},
		{
			name: "multiple days - Sunday",
			window: MaintenanceWindow{
				Days:      []string{"saturday", "sunday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			testTime: time.Date(2026, 2, 8, 4, 0, 0, 0, berlinLoc), // Sunday
			expected: true,
		},
		{
			name: "timezone conversion - UTC time in Berlin window",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			// 02:00 UTC = 03:00 Berlin (CET is UTC+1 in winter)
			testTime: time.Date(2026, 2, 7, 2, 0, 0, 0, utcLoc),
			expected: true,
		},
		{
			name: "timezone conversion - UTC time outside Berlin window",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			// 01:00 UTC = 02:00 Berlin (before window)
			testTime: time.Date(2026, 2, 7, 1, 0, 0, 0, utcLoc),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.window.IsInWindow(tt.testTime)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaintenanceWindowsConfigIsInAnyWindow(t *testing.T) {
	berlinLoc, _ := time.LoadLocation("Europe/Berlin")

	tests := []struct {
		name     string
		config   MaintenanceWindowsConfig
		testTime time.Time
		expected bool
	}{
		{
			name: "disabled - always returns true",
			config: MaintenanceWindowsConfig{
				Enabled: false,
				Windows: []MaintenanceWindow{},
			},
			testTime: time.Date(2026, 2, 7, 4, 0, 0, 0, berlinLoc),
			expected: true,
		},
		{
			name: "enabled - in first window",
			config: MaintenanceWindowsConfig{
				Enabled: true,
				Windows: []MaintenanceWindow{
					{
						Days:      []string{"saturday"},
						StartTime: "03:00",
						EndTime:   "05:00",
						Timezone:  "Europe/Berlin",
					},
					{
						Days:      []string{"wednesday"},
						StartTime: "02:00",
						EndTime:   "04:00",
						Timezone:  "Europe/Berlin",
					},
				},
			},
			testTime: time.Date(2026, 2, 7, 4, 0, 0, 0, berlinLoc), // Saturday 04:00
			expected: true,
		},
		{
			name: "enabled - in second window",
			config: MaintenanceWindowsConfig{
				Enabled: true,
				Windows: []MaintenanceWindow{
					{
						Days:      []string{"saturday"},
						StartTime: "03:00",
						EndTime:   "05:00",
						Timezone:  "Europe/Berlin",
					},
					{
						Days:      []string{"wednesday"},
						StartTime: "02:00",
						EndTime:   "04:00",
						Timezone:  "Europe/Berlin",
					},
				},
			},
			testTime: time.Date(2026, 2, 4, 3, 0, 0, 0, berlinLoc), // Wednesday 03:00
			expected: true,
		},
		{
			name: "enabled - not in any window",
			config: MaintenanceWindowsConfig{
				Enabled: true,
				Windows: []MaintenanceWindow{
					{
						Days:      []string{"saturday"},
						StartTime: "03:00",
						EndTime:   "05:00",
						Timezone:  "Europe/Berlin",
					},
				},
			},
			testTime: time.Date(2026, 2, 7, 10, 0, 0, 0, berlinLoc), // Saturday 10:00
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsInAnyWindow(tt.testTime)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaintenanceWindowsConfigGetActiveWindow(t *testing.T) {
	berlinLoc, _ := time.LoadLocation("Europe/Berlin")

	config := MaintenanceWindowsConfig{
		Enabled: true,
		Windows: []MaintenanceWindow{
			{
				Name:      "weekend-night",
				Days:      []string{"saturday", "sunday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			{
				Name:      "weekday-maintenance",
				Days:      []string{"wednesday"},
				StartTime: "02:00",
				EndTime:   "04:00",
				Timezone:  "Europe/Berlin",
			},
		},
	}

	t.Run("returns weekend window on Saturday", func(t *testing.T) {
		testTime := time.Date(2026, 2, 7, 4, 0, 0, 0, berlinLoc) // Saturday 04:00
		active := config.GetActiveWindow(testTime)
		require.NotNil(t, active)
		assert.Equal(t, "weekend-night", active.Name)
	})

	t.Run("returns weekday window on Wednesday", func(t *testing.T) {
		testTime := time.Date(2026, 2, 4, 3, 0, 0, 0, berlinLoc) // Wednesday 03:00
		active := config.GetActiveWindow(testTime)
		require.NotNil(t, active)
		assert.Equal(t, "weekday-maintenance", active.Name)
	})

	t.Run("returns nil when not in any window", func(t *testing.T) {
		testTime := time.Date(2026, 2, 7, 10, 0, 0, 0, berlinLoc) // Saturday 10:00
		active := config.GetActiveWindow(testTime)
		assert.Nil(t, active)
	})

	t.Run("returns nil when disabled", func(t *testing.T) {
		disabledConfig := MaintenanceWindowsConfig{Enabled: false}
		testTime := time.Date(2026, 2, 7, 4, 0, 0, 0, berlinLoc)
		active := disabledConfig.GetActiveWindow(testTime)
		assert.Nil(t, active)
	})
}

func TestMaintenanceWindowsConfigNextWindowStart(t *testing.T) {
	berlinLoc, _ := time.LoadLocation("Europe/Berlin")

	config := MaintenanceWindowsConfig{
		Enabled: true,
		Windows: []MaintenanceWindow{
			{
				Name:      "weekend-night",
				Days:      []string{"saturday", "sunday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
		},
	}

	t.Run("next window is today", func(t *testing.T) {
		// Saturday 02:00 - before window starts
		testTime := time.Date(2026, 2, 7, 2, 0, 0, 0, berlinLoc)
		next := config.NextWindowStart(testTime)

		expected := time.Date(2026, 2, 7, 3, 0, 0, 0, berlinLoc)
		assert.Equal(t, expected, next)
	})

	t.Run("next window is tomorrow (Sunday)", func(t *testing.T) {
		// Saturday 06:00 - after window ends
		testTime := time.Date(2026, 2, 7, 6, 0, 0, 0, berlinLoc)
		next := config.NextWindowStart(testTime)

		expected := time.Date(2026, 2, 8, 3, 0, 0, 0, berlinLoc) // Sunday 03:00
		assert.Equal(t, expected, next)
	})

	t.Run("next window is next week", func(t *testing.T) {
		// Monday 10:00 - need to wait until Saturday
		testTime := time.Date(2026, 2, 9, 10, 0, 0, 0, berlinLoc) // Monday
		next := config.NextWindowStart(testTime)

		expected := time.Date(2026, 2, 14, 3, 0, 0, 0, berlinLoc) // Next Saturday 03:00
		assert.Equal(t, expected, next)
	})

	t.Run("currently in window returns window start", func(t *testing.T) {
		// Saturday 04:00 - inside window
		testTime := time.Date(2026, 2, 7, 4, 0, 0, 0, berlinLoc)
		next := config.NextWindowStart(testTime)

		expected := time.Date(2026, 2, 7, 3, 0, 0, 0, berlinLoc) // Current window start
		assert.Equal(t, expected, next)
	})

	t.Run("disabled returns zero time", func(t *testing.T) {
		disabledConfig := MaintenanceWindowsConfig{Enabled: false}
		testTime := time.Date(2026, 2, 7, 4, 0, 0, 0, berlinLoc)
		next := disabledConfig.NextWindowStart(testTime)
		assert.True(t, next.IsZero())
	})
}

func TestMaintenanceWindowsConfigDurationUntilNextWindow(t *testing.T) {
	berlinLoc, _ := time.LoadLocation("Europe/Berlin")

	config := MaintenanceWindowsConfig{
		Enabled: true,
		Windows: []MaintenanceWindow{
			{
				Name:      "weekend-night",
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
		},
	}

	t.Run("returns duration until next window", func(t *testing.T) {
		// Saturday 02:00 - 1 hour before window starts
		testTime := time.Date(2026, 2, 7, 2, 0, 0, 0, berlinLoc)
		duration := config.DurationUntilNextWindow(testTime)

		assert.Equal(t, 1*time.Hour, duration)
	})

	t.Run("returns 0 when in window", func(t *testing.T) {
		// Saturday 04:00 - inside window
		testTime := time.Date(2026, 2, 7, 4, 0, 0, 0, berlinLoc)
		duration := config.DurationUntilNextWindow(testTime)

		assert.Equal(t, time.Duration(0), duration)
	})

	t.Run("returns 0 when disabled", func(t *testing.T) {
		disabledConfig := MaintenanceWindowsConfig{Enabled: false}
		testTime := time.Date(2026, 2, 7, 10, 0, 0, 0, berlinLoc)
		duration := disabledConfig.DurationUntilNextWindow(testTime)

		assert.Equal(t, time.Duration(0), duration)
	})
}

func TestMaintenanceWindowDifferentTimezones(t *testing.T) {
	// Test that the same UTC time is correctly evaluated in different timezones
	utcTime := time.Date(2026, 2, 7, 10, 0, 0, 0, time.UTC) // Saturday 10:00 UTC

	tests := []struct {
		name     string
		window   MaintenanceWindow
		expected bool
	}{
		{
			name: "UTC window 09:00-11:00",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "09:00",
				EndTime:   "11:00",
				Timezone:  "UTC",
			},
			expected: true, // 10:00 UTC is in window
		},
		{
			name: "Berlin window 10:00-12:00 (UTC+1)",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "10:00",
				EndTime:   "12:00",
				Timezone:  "Europe/Berlin",
			},
			expected: true, // 10:00 UTC = 11:00 Berlin, which is in window
		},
		{
			name: "New York window 04:00-06:00 (UTC-5)",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "04:00",
				EndTime:   "06:00",
				Timezone:  "America/New_York",
			},
			expected: true, // 10:00 UTC = 05:00 New York, which is in window
		},
		{
			name: "Tokyo window 19:00-21:00 (UTC+9)",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "19:00",
				EndTime:   "21:00",
				Timezone:  "Asia/Tokyo",
			},
			expected: true, // 10:00 UTC = 19:00 Tokyo, which is in window
		},
		{
			name: "Sydney window 20:00-22:00 (UTC+11 in Feb)",
			window: MaintenanceWindow{
				Days:      []string{"saturday"},
				StartTime: "20:00",
				EndTime:   "22:00",
				Timezone:  "Australia/Sydney",
			},
			expected: true, // 10:00 UTC = 21:00 Sydney (AEDT), which is in window
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.window.IsInWindow(utcTime)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMultipleWindowsNextStart(t *testing.T) {
	berlinLoc, _ := time.LoadLocation("Europe/Berlin")

	// Config with two windows - one closer than the other
	config := MaintenanceWindowsConfig{
		Enabled: true,
		Windows: []MaintenanceWindow{
			{
				Name:      "saturday-window",
				Days:      []string{"saturday"},
				StartTime: "03:00",
				EndTime:   "05:00",
				Timezone:  "Europe/Berlin",
			},
			{
				Name:      "wednesday-window",
				Days:      []string{"wednesday"},
				StartTime: "02:00",
				EndTime:   "04:00",
				Timezone:  "Europe/Berlin",
			},
		},
	}

	t.Run("picks closer window (Wednesday)", func(t *testing.T) {
		// Monday - Wednesday is closer than Saturday
		testTime := time.Date(2026, 2, 2, 10, 0, 0, 0, berlinLoc) // Monday
		next := config.NextWindowStart(testTime)

		expected := time.Date(2026, 2, 4, 2, 0, 0, 0, berlinLoc) // Wednesday 02:00
		assert.Equal(t, expected, next)
	})

	t.Run("picks closer window (Saturday)", func(t *testing.T) {
		// Thursday - Saturday is closer than next Wednesday
		testTime := time.Date(2026, 2, 5, 10, 0, 0, 0, berlinLoc) // Thursday
		next := config.NextWindowStart(testTime)

		expected := time.Date(2026, 2, 7, 3, 0, 0, 0, berlinLoc) // Saturday 03:00
		assert.Equal(t, expected, next)
	})
}
