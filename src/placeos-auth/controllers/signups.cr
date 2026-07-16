module PlaceOS::Auth
  # Manual signup endpoint (Doorkeeper/Ruby route `auth/signups#create`).
  #
  # The Ruby service only completed a signup when the request carried a
  # valid short-lived `social` cookie (set mid-callback for a not-yet-
  # existing OAuth user); every other request got 403. auth.cr creates
  # OAuth users inline in the provider callback and never issues that
  # cookie, so the "no valid social cookie" branch is the only reachable
  # one — this endpoint therefore always answers 403, which is exactly
  # what the legacy service returned for the same conditions.
  #
  # The route exists for wire parity (PPT-2536). Resurrecting the actual
  # user-creation path is a separate product decision — see
  # auth_migration/parity_matrix.md.
  class Signups < Application
    base "/auth"

    @[AC::Route::POST("/signup", status_code: HTTP::Status::FORBIDDEN)]
    def create : Nil
    end
  end
end
