import XCTest
@testable import PlatformControl

final class ResourceChartTimelineTests: XCTestCase {
    func testCursorAdvancesLinearlyAcrossPollBoundariesAndStalls() {
        let epoch = Date(timeIntervalSinceReferenceDate: 1000)
        let sample = epoch.addingTimeInterval(-10)
        var previous = ResourceChartTimeline.horizontalFraction(sample: sample, cursor: ResourceChartTimeline.presentationDate(now: epoch))
        // These frames span irregular poll arrivals and an extended source outage.
        for frame in 1...1200 {
            let now = epoch.addingTimeInterval(Double(frame) / 60)
            let cursor = ResourceChartTimeline.presentationDate(now: now)
            let position = ResourceChartTimeline.horizontalFraction(sample: sample, cursor: cursor)
            XCTAssertEqual(previous - position, 0.95 / 40 / 60, accuracy: 0.000000001)
            previous = position
        }
    }

    func testRealSegmentRevealsAtTimestampSpeedAcrossJitteredIntervals() {
        let start = Date(timeIntervalSinceReferenceDate: 1000)
        for interval in [1.8, 2.0, 2.4, 3.0] {
            let end = start.addingTimeInterval(interval)
            XCTAssertEqual(ResourceChartTimeline.segmentFraction(from: start, to: end, through: start.addingTimeInterval(interval / 2)), 0.5, accuracy: 0.000000001)
            XCTAssertEqual(ResourceChartTimeline.segmentFraction(from: start, to: end, through: end.addingTimeInterval(5)), 1)
            XCTAssertEqual(ResourceChartTimeline.segmentFraction(from: start, to: end, through: start.addingTimeInterval(-1)), 0)
        }
    }

    func testMissingAndStaleSamplesStartSeparateSegments() {
        let start = Date(timeIntervalSinceReferenceDate: 1000)
        XCTAssertTrue(ResourceChartTimeline.startsSegment(previous: nil, current: start))
        XCTAssertFalse(ResourceChartTimeline.startsSegment(previous: start, current: start.addingTimeInterval(2.4)))
        XCTAssertFalse(ResourceChartTimeline.startsSegment(previous: start, current: start.addingTimeInterval(6)))
        XCTAssertTrue(ResourceChartTimeline.startsSegment(previous: start, current: start.addingTimeInterval(6.01)))
    }

    func testWindowEdgesAndRightMargin() {
        let now = Date(timeIntervalSinceReferenceDate: 1000)
        let cursor = ResourceChartTimeline.presentationDate(now: now)
        XCTAssertEqual(now.timeIntervalSince(cursor), 3)
        XCTAssertEqual(ResourceChartTimeline.horizontalFraction(sample: cursor.addingTimeInterval(-40), cursor: cursor), 0)
        XCTAssertEqual(ResourceChartTimeline.horizontalFraction(sample: cursor, cursor: cursor), 0.95)
        XCTAssertLessThan(ResourceChartTimeline.horizontalFraction(sample: cursor.addingTimeInterval(-42), cursor: cursor), 0)
    }
}
