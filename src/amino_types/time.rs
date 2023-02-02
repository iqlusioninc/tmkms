//! Timestamps

use prost_amino_derive::Message;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tendermint::{
    error::Error,
    time::{ParseTimestamp, Time},
};
use tendermint_proto as proto;

#[derive(Clone, Eq, PartialEq, Message)]
pub struct TimeMsg {
    // TODO(ismail): switch to protobuf's well known type as soon as
    // https://github.com/tendermint/go-amino/pull/224 was merged
    // and tendermint caught up on the latest amino release.
    #[prost_amino(int64, tag = "1")]
    pub seconds: i64,
    #[prost_amino(int32, tag = "2")]
    pub nanos: i32,
}

impl ParseTimestamp for TimeMsg {
    fn parse_timestamp(&self) -> Result<Time, Error> {
        Time::from_unix_timestamp(self.seconds, self.nanos as u32)
    }
}

impl From<Time> for TimeMsg {
    fn from(ts: Time) -> TimeMsg {
        // TODO: non-panicking method for getting this?
        let duration = ts.duration_since(Time::unix_epoch()).unwrap();
        let seconds = duration.as_secs() as i64;
        let nanos = duration.subsec_nanos() as i32;

        TimeMsg { seconds, nanos }
    }
}

/// Converts `Time` to a `SystemTime`.
impl From<TimeMsg> for SystemTime {
    fn from(time: TimeMsg) -> SystemTime {
        if time.seconds >= 0 {
            UNIX_EPOCH + Duration::new(time.seconds as u64, time.nanos as u32)
        } else {
            UNIX_EPOCH - Duration::new(time.seconds as u64, time.nanos as u32)
        }
    }
}

impl From<TimeMsg> for proto::google::protobuf::Timestamp {
    fn from(ts: TimeMsg) -> proto::google::protobuf::Timestamp {
        proto::google::protobuf::Timestamp {
            seconds: ts.seconds,
            nanos: ts.nanos,
        }
    }
}

impl From<proto::google::protobuf::Timestamp> for TimeMsg {
    fn from(ts: proto::google::protobuf::Timestamp) -> TimeMsg {
        TimeMsg {
            seconds: ts.seconds,
            nanos: ts.nanos,
        }
    }
}
